# nf_conntrack_expand
In the current conntrack extend code, if we want to add a new extension, we must be add a new extension id and recompile kernel. I think that is not be convenient for users, so i add a new extension named NF_CT_EXT_EXPAND for supporting dynamic register/unregister expansion in runtime that means if kernel support NF_CT_EXT_EXPAND extension, user could call nf_ct_expand_area_add() to register a new expansion but not need to predefine an id in enum nf_ct_ext_id.