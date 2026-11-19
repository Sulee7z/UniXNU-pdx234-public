/* Cached diagnostics must remain available independently of a failed USB link. */
#include <assert.h>
#include <string.h>
#include "../ci/usb/PdxUsbDisplay.h"
int main(void)
{
    struct pdx_usb_display state = {0};
    char out[3][192], long_text[500];
    memset(long_text, 'x', sizeof long_text); long_text[499] = 0;
    assert(pdx_usb_display_set(&state, 0, "USB refused"));
    assert(pdx_usb_display_set(&state, 1, long_text));
    assert(!pdx_usb_display_set(&state, 3, "invalid"));
    assert(!pdx_usb_display_set(&state, 0, 0));
    assert(pdx_usb_display_get(&state, out));
    assert(!strcmp(out[0], "USB refused"));
    assert(strlen(out[1]) == 191 && out[2][0] == 0);
    state.busy = 1;
    assert(!pdx_usb_display_set(&state, 0, "lost"));
    assert(!pdx_usb_display_get(&state, out));
    assert(!strcmp(out[0], "USB refused"));
    state.busy = 0;
    assert(pdx_usb_display_get(&state, out));
    assert(!strcmp(out[0], "USB refused"));
    return 0;
}
