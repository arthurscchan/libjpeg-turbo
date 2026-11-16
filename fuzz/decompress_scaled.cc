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

/* This fuzzer exercises scaled decompression with all 12 supported scaling
   factors using the islow integer IDCT, at 8-bit and 12-bit data precision,
   as well as two code paths that no other fuzz target reaches:

   - The merged upsampler with 16-bit RGB565 output (jdmrg565.c and the
     non-565 paths of jdmerge.c).  use_merged_upsample() requires fast
     (non-fancy) upsampling, which none of the existing targets enables in
     combination with RGB565 output (and the TurboJPEG API does not even
     expose RGB565.)
   - The floating point IDCT (jidctflt.c) at full scale.  The existing
     decompress_libjpeg target requests JDCT_FLOAT, but the production
     coverage reports show that jidctflt.c is never executed.

   The existing TurboJPEG-based decompress targets only scale by 1/2 and 1/8,
   which exercise jidctred.c, so the scaled NxN islow IDCT variants in
   jidctint.c (3x3 through 16x16, at 8- and 12-bit precision; ~1500 lines)
   are dark in production coverage.  Since web browsers and image viewers
   routinely decompress attacker-provided JPEG files into scaled thumbnails,
   this is an attacker-reachable surface.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

extern "C" {
#include "../src/jpeglib.h"
#include "../src/jerror.h"
}


struct fuzzer_error_mgr {
  struct jpeg_error_mgr pub;
  jmp_buf setjmp_buffer;
};


static void fuzzer_error_exit(j_common_ptr cinfo)
{
  struct fuzzer_error_mgr *fuzz_err = (struct fuzzer_error_mgr *)cinfo->err;

  longjmp(fuzz_err->setjmp_buffer, 1);
}


static void fuzzer_emit_message(j_common_ptr cinfo, int msg_level)
{
}


/* The 12 scaling factors supported by libjpeg-turbo (numerator, denominator). */
static const struct {
  unsigned int num, denom;
} scalingFactors[12] = {
  { 2, 1 }, { 15, 8 }, { 7, 8 }, { 3, 4 }, { 5, 8 }, { 9, 16 },
  { 1, 2 }, { 3, 8 }, { 1, 4 }, { 3, 16 }, { 1, 8 }, { 1, 16 }
};

#define NUMSCALINGS  12


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  struct jpeg_decompress_struct cinfo;
  struct fuzzer_error_mgr jerr;
  /* volatile: these are modified between setjmp() and longjmp(), so without
     the qualifier their values would be indeterminate in the longjmp target
     and the row buffer could leak on the error exit path. */
  volatile JSAMPARRAY buffer = NULL;
  int row_stride = 0, ti;
  volatile int64_t sum = 0;

  /* Reject too-small input. */
  if (size < 2)
    return 0;

  cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.error_exit = fuzzer_error_exit;
  jerr.pub.emit_message = fuzzer_emit_message;

  jpeg_create_decompress(&cinfo);

  for (ti = 0; ti < NUMSCALINGS + 2; ti++) {
    boolean isMerged565Test = (ti == NUMSCALINGS);
    boolean isFloatTest = (ti == NUMSCALINGS + 1);
    int precision;

    if (setjmp(jerr.setjmp_buffer)) {
      jpeg_abort_decompress(&cinfo);
      /* Free the row buffer, since the longjmp bypasses the normal cleanup. */
      if (buffer) {
        free(buffer[0]);
        free(buffer);
        buffer = NULL;
      }
      continue;
    }

    jpeg_mem_src(&cinfo, data, (unsigned long)size);

    jpeg_read_header(&cinfo, TRUE);
    precision = cinfo.data_precision;

    /* Sanity check dimensions to avoid memory exhaustion.  Casting width to
       (uint64_t) prevents integer overflow if width * height > INT_MAX. */
    if (cinfo.image_width < 1 || cinfo.image_height < 1 ||
        (uint64_t)cinfo.image_width * cinfo.image_height > 1048576)
      goto bailout;

    /* 16-bit data is lossless-only and does not undergo IDCT or scaling. */
    if (precision == 16)
      continue;

    if (isMerged565Test) {
      /* Merged upsampling requires 8-bit data, fast (non-fancy) upsampling,
         YCbCr or RGB input with 3 components, and RGB565 output. */
      if (precision != 8 ||
          !(((cinfo.jpeg_color_space == JCS_YCbCr ||
              cinfo.jpeg_color_space == JCS_RGB) &&
             cinfo.num_components == 3)))
        continue;
      cinfo.scale_num = 1;
      cinfo.scale_denom = 1;
      cinfo.do_fancy_upsampling = FALSE;
      cinfo.out_color_space = JCS_RGB565;
      cinfo.dct_method = JDCT_ISLOW;
      /* Buffered-image mode disables merged upsampling, so only decode
         single-scan images in this test. */
      if (jpeg_has_multiple_scans(&cinfo))
        continue;
      cinfo.buffered_image = FALSE;
    } else if (isFloatTest) {
      cinfo.scale_num = cinfo.scale_denom = 1;
      cinfo.dct_method = JDCT_FLOAT;
      cinfo.buffered_image = jpeg_has_multiple_scans(&cinfo);
    } else {
      cinfo.scale_num = scalingFactors[ti].num;
      cinfo.scale_denom = scalingFactors[ti].denom;
      cinfo.dct_method = JDCT_ISLOW;
      cinfo.buffered_image = jpeg_has_multiple_scans(&cinfo);
    }

    if (!jpeg_start_decompress(&cinfo)) {
      jpeg_abort_decompress(&cinfo);
      continue;
    }

    row_stride = cinfo.output_width * cinfo.output_components;
    buffer = (JSAMPARRAY)malloc(sizeof(JSAMPROW));
    if (buffer == NULL)
      goto bailout;
    buffer[0] = NULL;
    buffer[0] = (JSAMPROW)malloc((size_t)row_stride *
                                 (precision > 8 ? sizeof(J12SAMPLE)
                                                : sizeof(JSAMPLE)));
    if (buffer[0] == NULL)
      goto bailout;

    if (cinfo.buffered_image) {
      /* Process all scans. */
      while (!jpeg_input_complete(&cinfo) &&
             cinfo.input_scan_number != cinfo.output_scan_number) {
        int retval;

        if (cinfo.input_scan_number > 100) {
          jpeg_abort_decompress(&cinfo);
          break;
        }

        /* Consume input data until we have a complete scan or reach the end
           of input. */
        do {
          retval = jpeg_consume_input(&cinfo);
        } while (retval != JPEG_SUSPENDED && retval != JPEG_REACHED_SOS &&
                 retval != JPEG_REACHED_EOI);

        if (retval == JPEG_REACHED_EOI)
          break;

        /* Start outputting the current scan. */
        if (!jpeg_start_output(&cinfo, cinfo.input_scan_number))
          break;

        while (cinfo.output_scanline < cinfo.output_height) {
          if (precision == 8) {
            if (jpeg_read_scanlines(&cinfo, buffer, 1) != 1)
              break;
          } else {
            if (jpeg12_read_scanlines(&cinfo, (J12SAMPARRAY)buffer, 1) != 1)
              break;
          }
          for (int i = 0; i < row_stride; i++)
            sum += (precision == 8) ?
                   ((JSAMPROW)buffer[0])[i] :
                   ((J12SAMPLE *)buffer[0])[i];
        }

        /* Finish this output pass. */
        if (!jpeg_finish_output(&cinfo))
          break;
      }
    } else {
      while (cinfo.output_scanline < cinfo.output_height) {
        if (precision == 8) {
          if (jpeg_read_scanlines(&cinfo, buffer, 1) != 1)
            break;
        } else {
          if (jpeg12_read_scanlines(&cinfo, (J12SAMPARRAY)buffer, 1) != 1)
            break;
        }
        for (int i = 0; i < row_stride; i++)
          sum += (precision == 8) ?
                 ((JSAMPROW)buffer[0])[i] :
                 ((J12SAMPLE *)buffer[0])[i];
      }
    }

    if (!cinfo.buffered_image)
      jpeg_finish_decompress(&cinfo);
    else
      jpeg_abort_decompress(&cinfo);

    free(buffer[0]);
    free(buffer);
    buffer = NULL;
  }

bailout:
  if (buffer) {
    free(buffer[0]);
    free(buffer);
  }
  jpeg_destroy_decompress(&cinfo);
  /* Prevent the sums above from being optimized out.  This test should never
     be true, but the compiler doesn't know that. */
  if (sum > (int64_t)4095 * 1048576 * 4 * (NUMSCALINGS + 2))
    return 1;
  return 0;
}
