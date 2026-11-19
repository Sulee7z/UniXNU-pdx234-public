// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "SonyPanel120.h"
#include "SonyPanelModes.generated.h"

extern "C" const SonyPanelModeFacts *sony_panel120_mode(unsigned id) {
    return id<4?&kSonyPanelModes[id]:nullptr;
}
extern "C" int native_sony_panel120_prepare(const SonyPanel120Snapshot *in,unsigned request,SonyPanel120Plan *out) {
    if(!out)return SonyPanel120Argument;
    *out={};
    if(!request)return SonyPanel120Disabled;
    if(request!=1 || !in)return SonyPanel120Argument;
    if(in->reserved || !in->owner_epoch || in->qualification!=SonyPanel120RequiredQualification)
        return SonyPanel120UnqualifiedOwner;
    const SonyPanelModeFacts *from=sony_panel120_mode(in->current_mode);
    if(!from)return SonyPanel120UnknownInheritedMode;
    if(in->gop_width!=from->width_per_link*from->links || in->gop_height!=from->height ||
       in->mdp_transfer_us!=from->mdp_transfer_us || in->bit_clock_hz[0]!=from->bit_clock_hz ||
       in->bit_clock_hz[1]!=from->bit_clock_hz)return SonyPanel120UnknownInheritedMode;
    // A plan marked no-change does not certify the actual TE cadence.
    if(from->hz==120)return SonyPanel120AlreadyRequestedMode;
    const SonyPanelModeFacts *to=sony_panel120_mode(in->current_mode+2);
    if(!to || from->hz!=60 || to->hz!=120 || from->width_per_link!=to->width_per_link ||
       from->height!=to->height || from->bit_clock_hz!=to->bit_clock_hz ||
       from->slice_width!=to->slice_width || from->slice_height!=to->slice_height)
        return SonyPanel120IncompatibleMode;
    for(unsigned i=0;i<14;++i)if(from->phy[i]!=to->phy[i])return SonyPanel120IncompatibleMode;
    *out={in->owner_epoch,from->id,to->id,120,to->mdp_transfer_us,
          to->id==2?kSonySwitch120Low:kSonySwitch120Native,
          to->id==2?sizeof(kSonySwitch120Low):sizeof(kSonySwitch120Native),
          7,1,1,1,(uint8_t)(from->mdp_transfer_us!=to->mdp_transfer_us),1,1,1,0};
    return SonyPanel120PlanReady;
}
extern "C" int sony_panel120_verify_external_te(const SonyPanel120Plan *plan,const SonyPanel120TeSample *sample) {
    if(!plan || !sample || !plan->owner_epoch || plan->target_hz!=120 || plan->to_mode<2 || plan->to_mode>3)
        return SonyPanel120Argument;
    if(sample->owner_epoch!=plan->owner_epoch || !sample->external_source_verified || !sample->batch_completed_both ||
       !sample->mdp_budget_verified || !sample->no_host_errors || sample->elapsed_us<1000000 || sample->elapsed_us>10000000)
        return SonyPanel120Unmeasured;
    for(unsigned i=0;i<2;++i) {
        const uint64_t rate=(uint64_t)sample->external_te_events[i]*1000000;
        if(rate<sample->elapsed_us*118 || rate>sample->elapsed_us*122 ||
           sample->min_period_us[i]<7900 || sample->max_period_us[i]>8800 ||
           sample->min_period_us[i]>sample->max_period_us[i])return SonyPanel120Not120;
    }
    return SonyPanel120Sample120;
}
