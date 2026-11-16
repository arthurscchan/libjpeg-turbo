/*
 * Copyright (C) 2026 D. R. Commander
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of the libjpeg-turbo Project nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS",
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* This fuzzer exercises the decompression-to-file output direction, i.e. the
   image writers used by djpeg and the tj3SaveImage*() functions:

   - The PPM/PGM writer (wrppm.c), including the 12- and 16-bit precision
     variants
   - The BMP writer (wrbmp.c), including the bottom-up row order, the row
     padding / pitch paths, and the density fields in the header
   - The PNG writer (wrpng.c and the bundled libspng/zlib libraries),
     including the iCCP chunk path when the JPEG source image contains an ICC
     profile in an APP2 marker

   None of the other fuzz targets write an output file, so these code paths
   (roughly 3000 lines of otherwise-dark code) are currently unreachable by
   the fuzzer corpus.  Since thumbnailers, image viewers, and photo managers
   routinely decompress attacker-provided JPEG files and re-encode them into
   PNG, BMP, and PPM output images, this is an attacker-reachable surface.
   Writing images of all three formats exercises, among other things, the
   BMP header and row-padding arithmetic, the PPM range-limit tables, the
   PNG chunking and CRC computation, and the zlib deflate stream generation.
 */

#include "../src/turbojpeg.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define NUMTESTS  9


struct savetest {
  const char *ext;
  enum TJPF pf;
  int bottomUp;
  int pitchPad;
  int densities;
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  tjhandle handle = NULL;
  void *dstBuf = NULL;
  int width = 0, height = 0, precision = 8, sampleSize, i;
  struct savetest tests[NUMTESTS] = {
    /*  Ext     Pixel Format  Bottom-Up  Pitch Pad  Densities  */
    { ".png",  TJPF_RGB,            0,         0,         0 },
    { ".bmp",  TJPF_BGR,            0,         0,         1 },
    { ".ppm",  TJPF_RGB,            1,         0,         0 },
    { ".png",  TJPF_GRAY,           0,         0,         0 },
    { ".bmp",  TJPF_GRAY,           0,         1,         1 },
    { ".ppm",  TJPF_GRAY,           0,         0,         0 },
    { ".png",  TJPF_BGRX,           0,         0,         0 },
    { ".ppm",  TJPF_RGB,            0,         1,         0 },
    { ".bmp",  TJPF_BGRX,           1,         1,         0 },
  };
  const char *tmpDir = getenv("TMPDIR");
  char filename[256];
  int64_t sum = 0;

  if (!tmpDir || !tmpDir[0])
    tmpDir = "/tmp";

  if ((handle = tj3Init(TJINIT_DECOMPRESS)) == NULL)
    goto bailout;

  /* We ignore the return value of tj3DecompressHeader(), because malformed
     JPEG images that might expose issues in libjpeg-turbo might also have
     header errors that cause tj3DecompressHeader() to fail. */
  tj3DecompressHeader(handle, data, size);
  width = tj3Get(handle, TJPARAM_JPEGWIDTH);
  height = tj3Get(handle, TJPARAM_JPEGHEIGHT);
  precision = tj3Get(handle, TJPARAM_PRECISION);
  sampleSize = (precision > 8 ? 2 : 1);

  /* Ignore 0-pixel images and images larger than 1 Megapixel, as the other
     fuzz targets do.  Casting width to (uint64_t) prevents integer overflow
     if width * height > INT_MAX. */
  if (width < 1 || height < 1 || (uint64_t)width * height > 1048576)
    goto bailout;

  if (!tj3Get(handle, TJPARAM_LOSSLESS))
    tj3Set(handle, TJPARAM_SCANLIMIT, 100);
  else
    tj3Set(handle, TJPARAM_SCANLIMIT, 50);

  for (i = 0; i < NUMTESTS; i++) {
    int w = width, h = height;
    int pf = tests[i].pf;
    int pitch = tests[i].pitchPad ? w * tjPixelSize[pf] + 3 : 0;
    int retval;

    tj3Set(handle, TJPARAM_BOTTOMUP, tests[i].bottomUp);
    if (tests[i].densities) {
      tj3Set(handle, TJPARAM_DENSITYUNITS, 2);
      tj3Set(handle, TJPARAM_XDENSITY, 300);
      tj3Set(handle, TJPARAM_YDENSITY, 300);
    } else {
      tj3Set(handle, TJPARAM_DENSITYUNITS, 0);
      tj3Set(handle, TJPARAM_XDENSITY, 1);
      tj3Set(handle, TJPARAM_YDENSITY, 1);
    }

    if ((dstBuf = tj3Alloc((size_t)(pitch ? pitch : w * tjPixelSize[pf]) *
                           (size_t)h * (size_t)sampleSize)) == NULL)
      goto bailout;

    if (precision == 8)
      retval = tj3Decompress8(handle, data, size, (unsigned char *)dstBuf,
                              pitch, pf);
    else if (precision == 12)
      retval = tj3Decompress12(handle, data, size, (short *)dstBuf,
                               pitch, pf);
    else
      retval = tj3Decompress16(handle, data, size, (unsigned short *)dstBuf,
                               pitch, pf);

    if (retval == 0) {
      /* Touch all of the decoded pixels in order to catch uninitialized reads
         when using MemorySanitizer. */
      int rowStride = (pitch ? pitch : w * tjPixelSize[pf]);

      if (precision == 8) {
        for (int row = 0; row < h; row++)
          for (int col = 0; col < w * tjPixelSize[pf]; col++)
            sum += ((unsigned char *)dstBuf)[row * (size_t)rowStride + col];
      } else {
        for (int row = 0; row < h; row++)
          for (int col = 0; col < w * tjPixelSize[pf]; col++)
            sum += ((unsigned short *)dstBuf)[row * (size_t)rowStride + col];
      }

      snprintf(filename, sizeof(filename), "%s/libjpeg-turbo_save_fuzzer%s",
               tmpDir, tests[i].ext);
      unlink(filename);
      if (precision == 8)
        retval = tj3SaveImage8(handle, filename, (unsigned char *)dstBuf, w,
                               pitch, h, pf);
      else if (precision == 12)
        retval = tj3SaveImage12(handle, filename, (short *)dstBuf, w, pitch,
                                h, pf);
      else
        retval = tj3SaveImage16(handle, filename, (unsigned short *)dstBuf, w,
                                pitch, h, pf);
      /* The save is expected to succeed for the supported precision and pixel
         format combinations and to cleanly fail for the others, so the return
         value is intentionally ignored. */
      (void)retval;
      unlink(filename);
    }

    tj3Free(dstBuf);
    dstBuf = NULL;
  }

bailout:
  tj3Free(dstBuf);
  tj3Destroy(handle);
  /* Prevent the sum above from being optimized out.  This test should never
     be true, but the compiler doesn't know that. */
  if (sum > (int64_t)((1LL << precision) - 1LL) * 1048576LL *
            tjPixelSize[TJPF_RGB] * NUMTESTS)
    return 1;
  return 0;
}
