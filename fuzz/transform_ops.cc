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

/* This fuzzer exercises the lossless transform operations and option
   combinations that the existing transform target does not use:

   - All 8 transform operations (TJXOP_NONE, HFLIP, VFLIP, TRANSPOSE,
     TRANSVERSE, ROT90, ROT180, ROT270) with default options.  The existing
     transform target only uses NONE, TRANSPOSE, ROT90, and ROT180, so the
     flip and transverse/270-degree code paths in transupp.c are dark.
   - The PERFECT and TRIM options with all of the transform operations
     (PERFECT is only possible when there are no partial iMCUs on the edges,
     so both the success and error paths are exercised.)
   - The CROP and GRAY options with all of the transform operations (the
     existing target only crops with TRANSPOSE), exercising the crop/rotate
     and crop/flip interactions in transupp.c.
   - The NOOUTPUT option, the PROGRESSIVE + ARITHMETIC + OPTIMIZE option
     combination, and the COPYNONE option with operations that the existing
     target does not use with them.

   Roughly 1179 lines of transupp.c are dark in production coverage.
   Since image managers routinely losslessly rotate and flip attacker-provided
   JPEG files, this is an attacker-reachable surface.  The transformation code
   allocates buffers and copies DCT coefficients based on the image
   dimensions and the transform operation, so it is a candidate for buffer
   overflow and integer overflow bugs.
 */

#include "../src/turbojpeg.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#define NUMOPS  8

/* Crop region origins: the region is adjusted to the iMCU alignment by
   transupp.c, so any in-bounds region exercises the adjustment code. */
#define CROP_X  32
#define CROP_Y  16


static int doTransform(tjhandle handle, const uint8_t *data, size_t size,
                       tjtransform *transform, unsigned char **dstBuf,
                       size_t *dstSize)
{
  size_t maxBufSize;

  *dstSize = maxBufSize = tj3TransformBufSize(handle, transform);
  if (maxBufSize == 0 || (*dstBuf = (unsigned char *)tj3Alloc(maxBufSize)) == NULL)
    return -1;

  /* The buffer is exactly sized, so prevent the internal machinery from
     reallocating it. */
  tj3Set(handle, TJPARAM_NOREALLOC, 1);
  return tj3Transform(handle, data, size, 1, dstBuf, dstSize, transform);
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  tjhandle handle = NULL;
  unsigned char *dstBuf = NULL;
  size_t dstSize = 0, sum;
  int width = 0, height = 0, jpegSubsamp, op, total = 0;

  if ((handle = tj3Init(TJINIT_TRANSFORM)) == NULL)
    goto bailout;

  /* We ignore the return value of tj3DecompressHeader(), because malformed
     JPEG images that might expose issues in libjpeg-turbo might also have
     header errors that cause tj3DecompressHeader() to fail. */
  tj3DecompressHeader(handle, data, size);
  width = tj3Get(handle, TJPARAM_JPEGWIDTH);
  height = tj3Get(handle, TJPARAM_JPEGHEIGHT);
  jpegSubsamp = tj3Get(handle, TJPARAM_SUBSAMP);
  /* Let the transform options dictate the entropy coding algorithm. */
  tj3Set(handle, TJPARAM_ARITHMETIC, 0);
  tj3Set(handle, TJPARAM_PROGRESSIVE, 0);
  tj3Set(handle, TJPARAM_OPTIMIZE, 0);

  /* Ignore 0-pixel images and images larger than 1 Megapixel.  Casting width
     to (uint64_t) prevents integer overflow if width * height > INT_MAX. */
  if (width < 1 || height < 1 || (uint64_t)width * height > 1048576)
    goto bailout;

  tj3Set(handle, TJPARAM_SCANLIMIT, 100);

  if (jpegSubsamp < 0 || jpegSubsamp >= TJ_NUMSAMP)
    jpegSubsamp = TJSAMP_444;

  for (op = 0; op < NUMOPS; op++) {
    tjtransform transform;

    /* Pass 1: all operations with default options. */
    memset(&transform, 0, sizeof(tjtransform));
    transform.op = op;
    if (doTransform(handle, data, size, &transform, &dstBuf, &dstSize) == 0) {
      sum = 0;
      for (size_t i = 0; i < dstSize; i++)
        sum += dstBuf[i];
      if (sum > 255 * dstSize + 1)
        goto bailout;
    }
    tj3Free(dstBuf);
    dstBuf = NULL;
    total++;
  }

  for (op = 0; op < NUMOPS; op++) {
    tjtransform transform;

    /* Pass 2: the PERFECT and TRIM options with all of the operations. */
    memset(&transform, 0, sizeof(tjtransform));
    transform.op = op;
    transform.options = TJXOPT_PERFECT | TJXOPT_TRIM;
    if (doTransform(handle, data, size, &transform, &dstBuf, &dstSize) == 0) {
      sum = 0;
      for (size_t i = 0; i < dstSize; i++)
        sum += dstBuf[i];
      if (sum > 255 * dstSize + 1)
        goto bailout;
    }
    tj3Free(dstBuf);
    dstBuf = NULL;
    total++;
  }

  for (op = 0; op < NUMOPS; op++) {
    tjtransform transform;

    /* Pass 3: the CROP and GRAY options with all of the operations. */
    memset(&transform, 0, sizeof(tjtransform));
    transform.op = op;
    transform.options = TJXOPT_CROP | TJXOPT_GRAY;
    transform.r.x = (width > CROP_X * 3) ? CROP_X : 0;
    transform.r.y = (height > CROP_Y * 3) ? CROP_Y : 0;
    transform.r.w = width / 2;
    transform.r.h = height / 2;
    if (doTransform(handle, data, size, &transform, &dstBuf, &dstSize) == 0) {
      sum = 0;
      for (size_t i = 0; i < dstSize; i++)
        sum += dstBuf[i];
      if (sum > 255 * dstSize + 1)
        goto bailout;
    }
    tj3Free(dstBuf);
    dstBuf = NULL;
    total++;
  }

  {
    tjtransform transform;

    /* Pass 4: option combinations the existing target does not use. */
    memset(&transform, 0, sizeof(tjtransform));
    transform.op = TJXOP_NONE;
    transform.options = TJXOPT_NOOUTPUT;
    if (doTransform(handle, data, size, &transform, &dstBuf, &dstSize) == 0) {
      sum = 0;
      for (size_t i = 0; i < dstSize; i++)
        sum += dstBuf[i];
      if (sum > 255 * dstSize + 1)
        goto bailout;
    }
    tj3Free(dstBuf);
    dstBuf = NULL;
    total++;

    memset(&transform, 0, sizeof(tjtransform));
    transform.op = TJXOP_ROT270;
    transform.options = TJXOPT_PROGRESSIVE | TJXOPT_ARITHMETIC |
                        TJXOPT_OPTIMIZE;
    if (doTransform(handle, data, size, &transform, &dstBuf, &dstSize) == 0) {
      sum = 0;
      for (size_t i = 0; i < dstSize; i++)
        sum += dstBuf[i];
      if (sum > 255 * dstSize + 1)
        goto bailout;
    }
    tj3Free(dstBuf);
    dstBuf = NULL;
    total++;

    memset(&transform, 0, sizeof(tjtransform));
    transform.op = TJXOP_VFLIP;
    transform.options = TJXOPT_COPYNONE;
    if (doTransform(handle, data, size, &transform, &dstBuf, &dstSize) == 0) {
      sum = 0;
      for (size_t i = 0; i < dstSize; i++)
        sum += dstBuf[i];
      if (sum > 255 * dstSize + 1)
        goto bailout;
    }
    tj3Free(dstBuf);
    dstBuf = NULL;
    total++;
  }

  /* Prevent the sums above from being optimized out.  This test should never
     be true, but the compiler doesn't know that. */
  if (total != NUMOPS * 3 + 3)
    return 1;

bailout:
  tj3Free(dstBuf);
  tj3Destroy(handle);
  return 0;
}
