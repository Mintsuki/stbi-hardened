# Fixes relative to upstream `nothings/stb`

Each line is one behavioural change made to `include/stb_image.h`. Upstream references (issue `#nnnn`, `PR #nnnn`, `CVE-…`) point at public discussion of the same bug; if a line has no reference, the fix was found locally.

## Integer / allocation helpers

- `stbi__malloc`: reject `size == 0` (malloc(0) is implementation-defined).
- `stbi__addsizes_valid`: reject negative `a` (previously only `b`).
- `stbi__mad{2,4}sizes_valid` / `stbi__malloc_mad{2,4}`: remove compile-time `#if` guards so every build has them.
- `stbi__malloc_mad{2,3,4}`: explicit `(size_t)` cast at the malloc boundary.

## I/O and context

- `stbi__refill_buffer`: clamp the `io.read` return value into `[0, buflen]`.
- `stbi__start_mem`: reject NULL buffer / non-positive length.
- `stbi__skip`: clamp skip count against end of buffer in memory mode.
- `stbi__getn`: reject `n < 0`; use pointer-difference to avoid wraparound.

## Format-conversion helpers

- `stbi__convert_format`: propagate NULL input; validate `req_comp` and `x`/`y` ranges. CVE-2023-43898, #1452, #1546, #1758, #1759, PR #1736.
- `stbi__convert_format16`: same + use `stbi__malloc_mad4` instead of raw `malloc`. #1860, #1932, #1936.
- `stbi__convert_16_to_8`, `stbi__convert_8_to_16`: overflow check via `mad{3,4}sizes_valid`; free the source buffer on allocation failure. #1529, #1936.

## Public API entry points

- NULL guards on filename / `FILE*` / `io_callbacks` struct / callback function pointers across every `stbi_load*` / `stbi_info*` / `stbi_is_hdr*` / `stbi_is_16_bit*`.
- Redirect NULL out-params (`x`/`y`/`z`/`comp`) to zero-initialised local dummies.
- Reject `req_comp` outside `[0, 4]` at `stbi__load_and_postprocess_*`. #1516.
- `stbi_zlib_decode_malloc_*` / `stbi_zlib_decode_*_buffer`: reject NULL / negative / oversize parameters.
- `stbi__load_main`: bail before reading `*x`/`*y`/`*comp` if `stbi__hdr_load` returned NULL.

## JPEG

- Zero-init `img_comp[i].data` / `.coeff` so unscanned progressive components don't IDCT heap garbage. #1535, #1595, #1928 bug 9.
- Track `sos_seen`; reject a decode that never entered a scan. #1608, PR #1624.

## PNG

- Tighter sample-count bound in IHDR (`1<<30` → `1<<29`) so downstream `raw_len` math stays in `int`. CVE-2025-2618, #1757.
- Reject invalid color-type / bit-depth combinations per PNG spec 11.2.2. #1928 bug 6.
- Reject chunk lengths above `INT_MAX` up front.
- `ioff + c.length` overflow check on IDAT accumulation; cap `idata_limit *= 2` at `INT_MAX/2`. #1928 bug 7.
- Validate each factor of `bpl*img_y*img_n + img_y` at IEND before use.
- Fix `(img_width_bytes + 1) * y` overflow in `stbi__create_png_image_raw`.
- Same fix in the Adam7 interlaced path; saturating `image_data_len -=`; explicit destination range check on the per-pass `memcpy`.
- Zero-init the `palette[1024]` stack buffer. #1861, #1928 bug 5.
- Zero-init `lencodes[]` in `stbi__compute_huffman_codes`.
- `stbi__fill_bits`: early-return if `num_bits >= 32` to keep `1U << num_bits` in defined range.
- zlib literal-run writer: explicit `(char)` cast on the stored byte. #1408.

## BMP

- Zero-init `pal[256][4]` so palette indices past `biClrUsed` decode as zeros. #1929, #1928 bug 10.
- OS/2 v1: `psize = (offset - extra_read - hsz) / 3` (was hardcoded `-24`). #1897.
- BITMAPV3INFOHEADER: read the embedded 16-byte RGBA mask block that was previously discarded. PR #1827, PR #1450.

## TGA

- Zero-init `tga_data`; propagate `stbi__getn` short-reads as a decode failure. CVE-2023-45663, #1542.

## PSD

- Require `channelCount >= 1` and `w > 0`, `h > 0`.
- Use `stbi__malloc_mad3(4, w, h, 0)` instead of `malloc(4 * w * h)`.
- White-matte unpremultiply: clamp each channel to `[0, 255]` / `[0, 65535]` before the narrowing cast.

## GIF

- Reject `w <= 0 || h <= 0` up front; use `malloc_mad3` for `out` / `background` / `history`.
- Image Descriptor: reject negatives; check `w > g->w - x` style to avoid sub-rect wrap.
- Animated path: overflow guards on `layers * stride` and `layers * sizeof(int)`. #1531, #1930.
- `two_back = out + (layers - 2) * stride` (was `out - 2 * stride`, pointing before the buffer). CVE-2023-45661, #1538, #1916, PR #1404.
- `stbi_load_gif_from_memory`: flip with `req_comp ? req_comp : *comp`, not `*comp`. CVE-2023-45662, #1540.
- Clear `*delays` after a `convert_format` failure and on the `gif_test` rejection path. CVE-2023-45664, CVE-2023-45666, CVE-2023-45667, #1544, #1548, #1550, PR #1839.
- `stbi__out_gif_code`: rewrite as an iterative prefix walk with a scratch buffer so deep dictionaries can't blow the stack. #1935.
- Move the ~80 KB `stbi__gif` struct onto the heap in `stbi__load_gif_main` and `stbi__gif_load`. PR #1592, PR #1882.

## HDR

- Require `width >= 1` and `height >= 1`.
- Flat-data path: zero-init `rgbe[]` and propagate `stbi__getn` short-reads as a decode failure. #1542.

## PIC

- `stbi__pic_load` returns NULL on `stbi__pic_load_core` failure instead of calling `stbi__convert_format(NULL, …)`. CVE-2023-43898, #1452, #1546, #1758, #1759, PR #1454.
- Pure-RLE and Mixed-RLE: reject zero-length runs to guarantee forward progress.

## PNM

- 16-bit samples are big-endian on disk; byte-swap to native after load. PR #1710, PR #1828.

## Defensive / portability

- `(size_t)` widening on the `memcpy`/`memset` multiplications in `create_png_image_raw` (depth=8 fast path), `stbi__pic_load` (canvas fill), `stbi__gif_load_next` (background copy, history clear), and `stbi__vertical_flip_slices`. PR #1658.
- `STBI_NOTUSED(s)` in `stbi__is_16_main` so an all-decoders-off build has no unused-parameter warning. PR #1467.
