#!/usr/bin/python

import binascii
import bisect
import commands
import copy
import optparse
import os
import pprint
import StringIO
import subprocess
import sys
import tempfile

# Local imports
import dict_utils
import file_extract
import term_colors

enable_colors = False
indent_width = 4
# DWARF DW_TAG defines
DW_TAG_array_type = 0x0001
DW_TAG_class_type = 0x0002
DW_TAG_entry_point = 0x0003
DW_TAG_enumeration_type = 0x0004
DW_TAG_formal_parameter = 0x0005
DW_TAG_imported_declaration = 0x0008
DW_TAG_label = 0x000A
DW_TAG_lexical_block = 0x000B
DW_TAG_member = 0x000D
DW_TAG_pointer_type = 0x000F
DW_TAG_reference_type = 0x0010
DW_TAG_compile_unit = 0x0011
DW_TAG_string_type = 0x0012
DW_TAG_structure_type = 0x0013
DW_TAG_subroutine_type = 0x0015
DW_TAG_typedef = 0x0016
DW_TAG_union_type = 0x0017
DW_TAG_unspecified_parameters = 0x0018
DW_TAG_variant = 0x0019
DW_TAG_common_block = 0x001A
DW_TAG_common_inclusion = 0x001B
DW_TAG_inheritance = 0x001C
DW_TAG_inlined_subroutine = 0x001D
DW_TAG_module = 0x001E
DW_TAG_ptr_to_member_type = 0x001F
DW_TAG_set_type = 0x0020
DW_TAG_subrange_type = 0x0021
DW_TAG_with_stmt = 0x0022
DW_TAG_access_declaration = 0x0023
DW_TAG_base_type = 0x0024
DW_TAG_catch_block = 0x0025
DW_TAG_const_type = 0x0026
DW_TAG_constant = 0x0027
DW_TAG_enumerator = 0x0028
DW_TAG_file_type = 0x0029
DW_TAG_friend = 0x002A
DW_TAG_namelist = 0x002B
DW_TAG_namelist_item = 0x002C
DW_TAG_packed_type = 0x002D
DW_TAG_subprogram = 0x002E
DW_TAG_template_type_parameter = 0x002F
DW_TAG_template_value_parameter = 0x0030
DW_TAG_thrown_type = 0x0031
DW_TAG_try_block = 0x0032
DW_TAG_variant_part = 0x0033
DW_TAG_variable = 0x0034
DW_TAG_volatile_type = 0x0035
DW_TAG_dwarf_procedure = 0x0036
DW_TAG_restrict_type = 0x0037
DW_TAG_interface_type = 0x0038
DW_TAG_namespace = 0x0039
DW_TAG_imported_module = 0x003A
DW_TAG_unspecified_type = 0x003B
DW_TAG_partial_unit = 0x003C
DW_TAG_imported_unit = 0x003D
DW_TAG_condition = 0x003F
DW_TAG_shared_type = 0x0040
DW_TAG_type_unit = 0x0041
DW_TAG_rvalue_reference_type = 0x0042
DW_TAG_template_alias = 0x0043
DW_TAG_MIPS_loop = 0x4081
DW_TAG_format_label = 0x4101
DW_TAG_function_template = 0x4102
DW_TAG_class_template = 0x4103
DW_TAG_GNU_template_template_param = 0x4106
DW_TAG_GNU_template_parameter_pack = 0x4107
DW_TAG_GNU_formal_parameter_pack = 0x4108
DW_TAG_APPLE_Property = 0x4200

DW_TAG_lo_user = 0x4080
DW_TAG_hi_user = 0xFFFF

DW_CHILDREN_no = 0
DW_CHILDREN_yes = 1

DW_AT_sibling = 0x0001
DW_AT_location = 0x0002
DW_AT_name = 0x0003
DW_AT_ordering = 0x0009
DW_AT_byte_size = 0x000B
DW_AT_bit_offset = 0x000C
DW_AT_bit_size = 0x000D
DW_AT_stmt_list = 0x0010
DW_AT_low_pc = 0x0011
DW_AT_high_pc = 0x0012
DW_AT_language = 0x0013
DW_AT_discr = 0x0015
DW_AT_discr_value = 0x0016
DW_AT_visibility = 0x0017
DW_AT_import = 0x0018
DW_AT_string_length = 0x0019
DW_AT_common_reference = 0x001A
DW_AT_comp_dir = 0x001B
DW_AT_const_value = 0x001C
DW_AT_containing_type = 0x001D
DW_AT_default_value = 0x001E
DW_AT_inline = 0x0020
DW_AT_is_optional = 0x0021
DW_AT_lower_bound = 0x0022
DW_AT_producer = 0x0025
DW_AT_prototyped = 0x0027
DW_AT_return_addr = 0x002A
DW_AT_start_scope = 0x002C
DW_AT_bit_stride = 0x002E
DW_AT_upper_bound = 0x002F
DW_AT_abstract_origin = 0x0031
DW_AT_accessibility = 0x0032
DW_AT_address_class = 0x0033
DW_AT_artificial = 0x0034
DW_AT_base_types = 0x0035
DW_AT_calling_convention = 0x0036
DW_AT_count = 0x0037
DW_AT_data_member_location = 0x0038
DW_AT_decl_column = 0x0039
DW_AT_decl_file = 0x003A
DW_AT_decl_line = 0x003B
DW_AT_declaration = 0x003C
DW_AT_discr_list = 0x003D
DW_AT_encoding = 0x003E
DW_AT_external = 0x003F
DW_AT_frame_base = 0x0040
DW_AT_friend = 0x0041
DW_AT_identifier_case = 0x0042
DW_AT_macro_info = 0x0043
DW_AT_namelist_item = 0x0044
DW_AT_priority = 0x0045
DW_AT_segment = 0x0046
DW_AT_specification = 0x0047
DW_AT_static_link = 0x0048
DW_AT_type = 0x0049
DW_AT_use_location = 0x004A
DW_AT_variable_parameter = 0x004B
DW_AT_virtuality = 0x004C
DW_AT_vtable_elem_location = 0x004D
DW_AT_allocated = 0x004E
DW_AT_associated = 0x004F
DW_AT_data_location = 0x0050
DW_AT_byte_stride = 0x0051
DW_AT_entry_pc = 0x0052
DW_AT_use_UTF8 = 0x0053
DW_AT_extension = 0x0054
DW_AT_ranges = 0x0055
DW_AT_trampoline = 0x0056
DW_AT_call_column = 0x0057
DW_AT_call_file = 0x0058
DW_AT_call_line = 0x0059
DW_AT_description = 0x005A
DW_AT_binary_scale = 0x005B
DW_AT_decimal_scale = 0x005C
DW_AT_small = 0x005D
DW_AT_decimal_sign = 0x005E
DW_AT_digit_count = 0x005F
DW_AT_picture_string = 0x0060
DW_AT_mutable = 0x0061
DW_AT_threads_scaled = 0x0062
DW_AT_explicit = 0x0063
DW_AT_object_pointer = 0x0064
DW_AT_endianity = 0x0065
DW_AT_elemental = 0x0066
DW_AT_pure = 0x0067
DW_AT_recursive = 0x0068
DW_AT_signature = 0x0069
DW_AT_main_subprogram = 0x006a
DW_AT_data_bit_offset = 0x006b
DW_AT_const_expr = 0x006c
DW_AT_enum_class = 0x006d
DW_AT_linkage_name = 0x006e

DW_AT_string_length_bit_size = 0x006f
DW_AT_string_length_byte_size = 0x0070
DW_AT_rank = 0x0071
DW_AT_str_offsets_base = 0x0072
DW_AT_addr_base = 0x0073
DW_AT_ranges_base = 0x0074
DW_AT_dwo_id = 0x0075
DW_AT_dwo_name = 0x0076

DW_AT_reference = 0x0077
DW_AT_rvalue_reference = 0x0078

DW_AT_lo_user = 0x2000
DW_AT_hi_user = 0x3FFF
DW_AT_MIPS_fde = 0x2001
DW_AT_MIPS_loop_begin = 0x2002
DW_AT_MIPS_tail_loop_begin = 0x2003
DW_AT_MIPS_epilog_begin = 0x2004
DW_AT_MIPS_loop_unroll_factor = 0x2005
DW_AT_MIPS_software_pipeline_depth = 0x2006
DW_AT_MIPS_linkage_name = 0x2007
DW_AT_MIPS_stride = 0x2008
DW_AT_MIPS_abstract_name = 0x2009
DW_AT_MIPS_clone_origin = 0x200A
DW_AT_MIPS_has_inlines = 0x200B
DW_AT_MIPS_stride_byte = 0x200C
DW_AT_MIPS_stride_elem = 0x200D
DW_AT_MIPS_ptr_dopetype = 0x200E
DW_AT_MIPS_allocatable_dopetype = 0x200F
DW_AT_MIPS_assumed_shape_dopetype = 0x2010
DW_AT_MIPS_assumed_size = 0x2011

DW_AT_sf_names = 0x2101
DW_AT_src_info = 0x2102
DW_AT_mac_info = 0x2103
DW_AT_src_coords = 0x2104
DW_AT_body_begin = 0x2105
DW_AT_body_end = 0x2106
DW_AT_GNU_vector = 0x2107
DW_AT_GNU_odr_signature = 0x210f
DW_AT_GNU_template_name = 0x2110
DW_AT_GNU_all_tail_call_sites = 0x2116
DW_AT_APPLE_repository_file = 0x2501
DW_AT_APPLE_repository_type = 0x2502
DW_AT_APPLE_repository_name = 0x2503
DW_AT_APPLE_repository_specification = 0x2504
DW_AT_APPLE_repository_import = 0x2505
DW_AT_APPLE_repository_abstract_origin = 0x2506


DW_AT_APPLE_optimized = 0x3FE1
DW_AT_APPLE_flags = 0x3FE2
DW_AT_APPLE_isa = 0x3FE3
DW_AT_APPLE_block = 0x3FE4
DW_AT_APPLE_major_runtime_vers = 0x3FE5
DW_AT_APPLE_runtime_class = 0x3FE6
DW_AT_APPLE_omit_frame_ptr = 0x3FE7
DW_AT_APPLE_property_name = 0x3fe8
DW_AT_APPLE_property_getter = 0x3fe9
DW_AT_APPLE_property_setter = 0x3fea
DW_AT_APPLE_property_attribute = 0x3feb
DW_AT_APPLE_objc_complete_type = 0x3fec
DW_AT_APPLE_property = 0x3fed

DW_FORM_addr = 0x01
DW_FORM_block2 = 0x03
DW_FORM_block4 = 0x04
DW_FORM_data2 = 0x05
DW_FORM_data4 = 0x06
DW_FORM_data8 = 0x07
DW_FORM_string = 0x08
DW_FORM_block = 0x09
DW_FORM_block1 = 0x0A
DW_FORM_data1 = 0x0B
DW_FORM_flag = 0x0C
DW_FORM_sdata = 0x0D
DW_FORM_strp = 0x0E
DW_FORM_udata = 0x0F
DW_FORM_ref_addr = 0x10
DW_FORM_ref1 = 0x11
DW_FORM_ref2 = 0x12
DW_FORM_ref4 = 0x13
DW_FORM_ref8 = 0x14
DW_FORM_ref_udata = 0x15
DW_FORM_indirect = 0x16
DW_FORM_sec_offset = 0x17
DW_FORM_exprloc = 0x18
DW_FORM_flag_present = 0x19
DW_FORM_ref_sig8 = 0x20
DW_FORM_GNU_addr_index = 0x1f01
DW_FORM_GNU_str_index = 0x1f02

DW_OP_addr = 0x03
DW_OP_deref = 0x06
DW_OP_const1u = 0x08
DW_OP_const1s = 0x09
DW_OP_const2u = 0x0A
DW_OP_const2s = 0x0B
DW_OP_const4u = 0x0C
DW_OP_const4s = 0x0D
DW_OP_const8u = 0x0E
DW_OP_const8s = 0x0F
DW_OP_constu = 0x10
DW_OP_consts = 0x11
DW_OP_dup = 0x12
DW_OP_drop = 0x13
DW_OP_over = 0x14
DW_OP_pick = 0x15
DW_OP_swap = 0x16
DW_OP_rot = 0x17
DW_OP_xderef = 0x18
DW_OP_abs = 0x19
DW_OP_and = 0x1A
DW_OP_div = 0x1B
DW_OP_minus = 0x1C
DW_OP_mod = 0x1D
DW_OP_mul = 0x1E
DW_OP_neg = 0x1F
DW_OP_not = 0x20
DW_OP_or = 0x21
DW_OP_plus = 0x22
DW_OP_plus_uconst = 0x23
DW_OP_shl = 0x24
DW_OP_shr = 0x25
DW_OP_shra = 0x26
DW_OP_xor = 0x27
DW_OP_skip = 0x2F
DW_OP_bra = 0x28
DW_OP_eq = 0x29
DW_OP_ge = 0x2A
DW_OP_gt = 0x2B
DW_OP_le = 0x2C
DW_OP_lt = 0x2D
DW_OP_ne = 0x2E
DW_OP_lit0 = 0x30
DW_OP_lit1 = 0x31
DW_OP_lit2 = 0x32
DW_OP_lit3 = 0x33
DW_OP_lit4 = 0x34
DW_OP_lit5 = 0x35
DW_OP_lit6 = 0x36
DW_OP_lit7 = 0x37
DW_OP_lit8 = 0x38
DW_OP_lit9 = 0x39
DW_OP_lit10 = 0x3A
DW_OP_lit11 = 0x3B
DW_OP_lit12 = 0x3C
DW_OP_lit13 = 0x3D
DW_OP_lit14 = 0x3E
DW_OP_lit15 = 0x3F
DW_OP_lit16 = 0x40
DW_OP_lit17 = 0x41
DW_OP_lit18 = 0x42
DW_OP_lit19 = 0x43
DW_OP_lit20 = 0x44
DW_OP_lit21 = 0x45
DW_OP_lit22 = 0x46
DW_OP_lit23 = 0x47
DW_OP_lit24 = 0x48
DW_OP_lit25 = 0x49
DW_OP_lit26 = 0x4A
DW_OP_lit27 = 0x4B
DW_OP_lit28 = 0x4C
DW_OP_lit29 = 0x4D
DW_OP_lit30 = 0x4E
DW_OP_lit31 = 0x4F
DW_OP_reg0 = 0x50
DW_OP_reg1 = 0x51
DW_OP_reg2 = 0x52
DW_OP_reg3 = 0x53
DW_OP_reg4 = 0x54
DW_OP_reg5 = 0x55
DW_OP_reg6 = 0x56
DW_OP_reg7 = 0x57
DW_OP_reg8 = 0x58
DW_OP_reg9 = 0x59
DW_OP_reg10 = 0x5A
DW_OP_reg11 = 0x5B
DW_OP_reg12 = 0x5C
DW_OP_reg13 = 0x5D
DW_OP_reg14 = 0x5E
DW_OP_reg15 = 0x5F
DW_OP_reg16 = 0x60
DW_OP_reg17 = 0x61
DW_OP_reg18 = 0x62
DW_OP_reg19 = 0x63
DW_OP_reg20 = 0x64
DW_OP_reg21 = 0x65
DW_OP_reg22 = 0x66
DW_OP_reg23 = 0x67
DW_OP_reg24 = 0x68
DW_OP_reg25 = 0x69
DW_OP_reg26 = 0x6A
DW_OP_reg27 = 0x6B
DW_OP_reg28 = 0x6C
DW_OP_reg29 = 0x6D
DW_OP_reg30 = 0x6E
DW_OP_reg31 = 0x6F
DW_OP_breg0 = 0x70
DW_OP_breg1 = 0x71
DW_OP_breg2 = 0x72
DW_OP_breg3 = 0x73
DW_OP_breg4 = 0x74
DW_OP_breg5 = 0x75
DW_OP_breg6 = 0x76
DW_OP_breg7 = 0x77
DW_OP_breg8 = 0x78
DW_OP_breg9 = 0x79
DW_OP_breg10 = 0x7A
DW_OP_breg11 = 0x7B
DW_OP_breg12 = 0x7C
DW_OP_breg13 = 0x7D
DW_OP_breg14 = 0x7E
DW_OP_breg15 = 0x7F
DW_OP_breg16 = 0x80
DW_OP_breg17 = 0x81
DW_OP_breg18 = 0x82
DW_OP_breg19 = 0x83
DW_OP_breg20 = 0x84
DW_OP_breg21 = 0x85
DW_OP_breg22 = 0x86
DW_OP_breg23 = 0x87
DW_OP_breg24 = 0x88
DW_OP_breg25 = 0x89
DW_OP_breg26 = 0x8A
DW_OP_breg27 = 0x8B
DW_OP_breg28 = 0x8C
DW_OP_breg29 = 0x8D
DW_OP_breg30 = 0x8E
DW_OP_breg31 = 0x8F
DW_OP_regx = 0x90
DW_OP_fbreg = 0x91
DW_OP_bregx = 0x92
DW_OP_piece = 0x93
DW_OP_deref_size = 0x94
DW_OP_xderef_size = 0x95
DW_OP_nop = 0x96
DW_OP_push_object_address = 0x97
DW_OP_call2 = 0x98
DW_OP_call4 = 0x99
DW_OP_call_ref = 0x9A
DW_OP_form_tls_address = 0x9B
DW_OP_call_frame_cfa = 0x9C
DW_OP_bit_piece = 0x9D
DW_OP_implicit_value = 0x9E
DW_OP_stack_value = 0x9F
DW_OP_lo_user = 0xE0
DW_OP_GNU_push_tls_address = 0xE0
DW_OP_APPLE_uninit = 0xF0
DW_OP_hi_user = 0xFF

DW_ATE_address = 0x01
DW_ATE_boolean = 0x02
DW_ATE_complex_float = 0x03
DW_ATE_float = 0x04
DW_ATE_signed = 0x05
DW_ATE_signed_char = 0x06
DW_ATE_unsigned = 0x07
DW_ATE_unsigned_char = 0x08
DW_ATE_imaginary_float = 0x09
DW_ATE_packed_decimal = 0x0A
DW_ATE_numeric_string = 0x0B
DW_ATE_edited = 0x0C
DW_ATE_signed_fixed = 0x0D
DW_ATE_unsigned_fixed = 0x0E
DW_ATE_decimal_float = 0x0F
DW_ATE_UTF = 0x10
DW_ATE_lo_user = 0x80
DW_ATE_hi_user = 0xFF

DW_DS_unsigned = 0x01
DW_DS_leading_overpunch = 0x02
DW_DS_trailing_overpunch = 0x03
DW_DS_leading_separate = 0x04
DW_DS_trailing_separate = 0x05


DW_END_default = 0x00
DW_END_big = 0x01
DW_END_little = 0x02
DW_END_lo_user = 0x40
DW_END_hi_user = 0xFF

DW_ACCESS_public = 0x01
DW_ACCESS_protected = 0x02
DW_ACCESS_private = 0x03

DW_VIS_local = 0x01
DW_VIS_exported = 0x02
DW_VIS_qualified = 0x03

DW_VIRTUALITY_none = 0x00
DW_VIRTUALITY_virtual = 0x01
DW_VIRTUALITY_pure_virtual = 0x02

DW_LANG_C89 = 0x0001
DW_LANG_C = 0x0002
DW_LANG_Ada83 = 0x0003
DW_LANG_C_plus_plus = 0x0004
DW_LANG_Cobol74 = 0x0005
DW_LANG_Cobol85 = 0x0006
DW_LANG_Fortran77 = 0x0007
DW_LANG_Fortran90 = 0x0008
DW_LANG_Pascal83 = 0x0009
DW_LANG_Modula2 = 0x000A
DW_LANG_Java = 0x000B
DW_LANG_C99 = 0x000C
DW_LANG_Ada95 = 0x000D
DW_LANG_Fortran95 = 0x000E
DW_LANG_PLI = 0x000F
DW_LANG_ObjC = 0x0010
DW_LANG_ObjC_plus_plus = 0x0011
DW_LANG_UPC = 0x0012
DW_LANG_D = 0x0013
DW_LANG_Python = 0x0014
DW_LANG_OpenCL = 0x0015
DW_LANG_Go = 0x0016
DW_LANG_Modula3 = 0x0017
DW_LANG_Haskell = 0x0018
DW_LANG_C_plus_plus_03 = 0x0019
DW_LANG_C_plus_plus_11 = 0x001a
DW_LANG_OCaml = 0x001b
DW_LANG_Rust = 0x001c
DW_LANG_C11 = 0x001d
DW_LANG_Swift = 0x001e
DW_LANG_Julia = 0x001f
DW_LANG_lo_user = 0x8000
DW_LANG_hi_user = 0xFFFF

DW_ID_case_sensitive = 0x00
DW_ID_up_case = 0x01
DW_ID_down_case = 0x02
DW_ID_case_insensitive = 0x03

DW_CC_normal = 0x01
DW_CC_program = 0x02
DW_CC_nocall = 0x03
DW_CC_lo_user = 0x40
DW_CC_hi_user = 0xFF

DW_INL_not_inlined = 0x00
DW_INL_inlined = 0x01
DW_INL_declared_not_inlined = 0x02
DW_INL_declared_inlined = 0x03

DW_ORD_row_major = 0x00
DW_ORD_col_major = 0x01

DW_DSC_label = 0x00
DW_DSC_range = 0x01

DW_LNS_copy = 0x01
DW_LNS_advance_pc = 0x02
DW_LNS_advance_line = 0x03
DW_LNS_set_file = 0x04
DW_LNS_set_column = 0x05
DW_LNS_negate_stmt = 0x06
DW_LNS_set_basic_block = 0x07
DW_LNS_const_add_pc = 0x08
DW_LNS_fixed_advance_pc = 0x09
DW_LNS_set_prologue_end = 0x0A
DW_LNS_set_epilogue_begin = 0x0B
DW_LNS_set_isa = 0x0C

DW_LNE_end_sequence = 0x01
DW_LNE_set_address = 0x02
DW_LNE_define_file = 0x03
DW_LNE_set_discriminator = 0x04
DW_LNE_lo_user = 0x80
DW_LNE_hi_user = 0xFF

DW_MACINFO_define = 0x01
DW_MACINFO_undef = 0x02
DW_MACINFO_start_file = 0x03
DW_MACINFO_end_file = 0x04
DW_MACINFO_vendor_ext = 0xFF

DW_CFA_advance_loc = 0x40
DW_CFA_offset = 0x80
DW_CFA_restore = 0xC0
DW_CFA_nop = 0x00
DW_CFA_set_loc = 0x01
DW_CFA_advance_loc1 = 0x02
DW_CFA_advance_loc2 = 0x03
DW_CFA_advance_loc4 = 0x04
DW_CFA_offset_extended = 0x05
DW_CFA_restore_extended = 0x06
DW_CFA_undefined = 0x07
DW_CFA_same_value = 0x08
DW_CFA_register = 0x09
DW_CFA_remember_state = 0x0A
DW_CFA_restore_state = 0x0B
DW_CFA_def_cfa = 0x0C
DW_CFA_def_cfa_register = 0x0D
DW_CFA_def_cfa_offset = 0x0E
DW_CFA_def_cfa_expression = 0x0F
DW_CFA_expression = 0x10
DW_CFA_offset_extended_sf = 0x11
DW_CFA_def_cfa_sf = 0x12
DW_CFA_def_cfa_offset_sf = 0x13
DW_CFA_val_offset = 0x14
DW_CFA_val_offset_sf = 0x15
DW_CFA_val_expression = 0x16
DW_CFA_GNU_window_save = 0x2D
DW_CFA_GNU_args_size = 0x2E
DW_CFA_GNU_negative_offset_extended = 0x2F
DW_CFA_lo_user = 0x1C
DW_CFA_hi_user = 0x3F

DW_GNU_EH_PE_absptr = 0x00
DW_GNU_EH_PE_uleb128 = 0x01
DW_GNU_EH_PE_udata2 = 0x02
DW_GNU_EH_PE_udata4 = 0x03
DW_GNU_EH_PE_udata8 = 0x04
DW_GNU_EH_PE_sleb128 = 0x09
DW_GNU_EH_PE_sdata2 = 0x0A
DW_GNU_EH_PE_sdata4 = 0x0B
DW_GNU_EH_PE_sdata8 = 0x0C
DW_GNU_EH_PE_signed = 0x08
DW_GNU_EH_PE_MASK_ENCODING = 0x0F
DW_GNU_EH_PE_pcrel = 0x10
DW_GNU_EH_PE_textrel = 0x20
DW_GNU_EH_PE_datarel = 0x30
DW_GNU_EH_PE_funcrel = 0x40
DW_GNU_EH_PE_aligned = 0x50
DW_GNU_EH_PE_indirect = 0x80
DW_GNU_EH_PE_omit = 0xFF

DW_APPLE_PROPERTY_readonly = 0x01
DW_APPLE_PROPERTY_readwrite = 0x02
DW_APPLE_PROPERTY_assign = 0x04
DW_APPLE_PROPERTY_retain = 0x08
DW_APPLE_PROPERTY_copy = 0x10
DW_APPLE_PROPERTY_nonatomic = 0x20

DW_UT_compile = 0x01
DW_UT_type = 0x02
DW_UT_partial = 0x03
DW_UT_skeleton = 0x04
DW_UT_split_compile = 0x05
DW_UT_split_type = 0x06


def is_string(value):
    return isinstance(value, basestring)


def tag_is_variable(tag):
    if tag == DW_TAG_variable:
        return True
    if tag == DW_TAG_formal_parameter:
        return True
    return False


def tag_is_type(tag):
    if tag == DW_TAG_class_type:
        return True
    if tag == DW_TAG_enumeration_type:
        return True
    if tag == DW_TAG_string_type:
        return True
    if tag == DW_TAG_structure_type:
        return True
    if tag == DW_TAG_union_type:
        return True
    if tag == DW_TAG_set_type:
        return True
    if tag == DW_TAG_base_type:
        return True
    if tag == DW_TAG_packed_type:
        return True
    if tag == DW_TAG_thrown_type:
        return True
    if tag == DW_TAG_interface_type:
        return True
    if tag == DW_TAG_unspecified_type:
        return True
    if tag == DW_TAG_shared_type:
        return True
    return False


def get_uleb128_byte_size(value):
    byte_size = 1
    while value >= 0x80:
        byte_size += 1
        value >>= 7
    return byte_size


def dump_block(data, outfile):

    data_len = len(data)
    print >>outfile, '<%u>' % (data_len),
    for byte in data:
        print >>outfile, binascii.hexlify(byte),


class DWARFInfo:
    '''DWARF information that carries the DWARF version, address byte size,
       and DWARF32/DWARF64'''
    def __init__(self, version, addr_size, dwarf_size, byte_order='='):
        self.version = version  # DWARF version number
        self.addr_size = addr_size  # Size in bytes of an address
        self.dwarf_size = dwarf_size  # 4 for DWARF32 or 8 for DWARF64
        self.byte_order = byte_order

    def isDWARF32(self):
        return self.dwarf_size == 4


class Tag(dict_utils.Enum):
    enum = {
        'DW_TAG_NULL': 0,
        'DW_TAG_array_type': DW_TAG_array_type,
        'DW_TAG_class_type': DW_TAG_class_type,
        'DW_TAG_entry_point': DW_TAG_entry_point,
        'DW_TAG_enumeration_type': DW_TAG_enumeration_type,
        'DW_TAG_formal_parameter': DW_TAG_formal_parameter,
        'DW_TAG_imported_declaration': DW_TAG_imported_declaration,
        'DW_TAG_label': DW_TAG_label,
        'DW_TAG_lexical_block': DW_TAG_lexical_block,
        'DW_TAG_member': DW_TAG_member,
        'DW_TAG_pointer_type': DW_TAG_pointer_type,
        'DW_TAG_reference_type': DW_TAG_reference_type,
        'DW_TAG_compile_unit': DW_TAG_compile_unit,
        'DW_TAG_string_type': DW_TAG_string_type,
        'DW_TAG_structure_type': DW_TAG_structure_type,
        'DW_TAG_subroutine_type': DW_TAG_subroutine_type,
        'DW_TAG_typedef': DW_TAG_typedef,
        'DW_TAG_union_type': DW_TAG_union_type,
        'DW_TAG_unspecified_parameters': DW_TAG_unspecified_parameters,
        'DW_TAG_variant': DW_TAG_variant,
        'DW_TAG_common_block': DW_TAG_common_block,
        'DW_TAG_common_inclusion': DW_TAG_common_inclusion,
        'DW_TAG_inheritance': DW_TAG_inheritance,
        'DW_TAG_inlined_subroutine': DW_TAG_inlined_subroutine,
        'DW_TAG_module': DW_TAG_module,
        'DW_TAG_ptr_to_member_type': DW_TAG_ptr_to_member_type,
        'DW_TAG_set_type': DW_TAG_set_type,
        'DW_TAG_subrange_type': DW_TAG_subrange_type,
        'DW_TAG_with_stmt': DW_TAG_with_stmt,
        'DW_TAG_access_declaration': DW_TAG_access_declaration,
        'DW_TAG_base_type': DW_TAG_base_type,
        'DW_TAG_catch_block': DW_TAG_catch_block,
        'DW_TAG_const_type': DW_TAG_const_type,
        'DW_TAG_constant': DW_TAG_constant,
        'DW_TAG_enumerator': DW_TAG_enumerator,
        'DW_TAG_file_type': DW_TAG_file_type,
        'DW_TAG_friend': DW_TAG_friend,
        'DW_TAG_namelist': DW_TAG_namelist,
        'DW_TAG_namelist_item': DW_TAG_namelist_item,
        'DW_TAG_packed_type': DW_TAG_packed_type,
        'DW_TAG_subprogram': DW_TAG_subprogram,
        'DW_TAG_template_type_parameter': DW_TAG_template_type_parameter,
        'DW_TAG_template_value_parameter': DW_TAG_template_value_parameter,
        'DW_TAG_thrown_type': DW_TAG_thrown_type,
        'DW_TAG_try_block': DW_TAG_try_block,
        'DW_TAG_variant_part': DW_TAG_variant_part,
        'DW_TAG_variable': DW_TAG_variable,
        'DW_TAG_volatile_type': DW_TAG_volatile_type,
        'DW_TAG_dwarf_procedure': DW_TAG_dwarf_procedure,
        'DW_TAG_restrict_type': DW_TAG_restrict_type,
        'DW_TAG_interface_type': DW_TAG_interface_type,
        'DW_TAG_namespace': DW_TAG_namespace,
        'DW_TAG_imported_module': DW_TAG_imported_module,
        'DW_TAG_unspecified_type': DW_TAG_unspecified_type,
        'DW_TAG_partial_unit': DW_TAG_partial_unit,
        'DW_TAG_imported_unit': DW_TAG_imported_unit,
        'DW_TAG_condition': DW_TAG_condition,
        'DW_TAG_shared_type': DW_TAG_shared_type,
        'DW_TAG_type_unit': DW_TAG_type_unit,
        'DW_TAG_rvalue_reference_type': DW_TAG_rvalue_reference_type,
        'DW_TAG_template_alias': DW_TAG_template_alias,
        'DW_TAG_MIPS_loop': DW_TAG_MIPS_loop,
        'DW_TAG_format_label': DW_TAG_format_label,
        'DW_TAG_function_template': DW_TAG_function_template,
        'DW_TAG_class_template': DW_TAG_class_template,
        'DW_TAG_GNU_template_template_param':
            DW_TAG_GNU_template_template_param,
        'DW_TAG_GNU_template_parameter_pack':
            DW_TAG_GNU_template_parameter_pack,
        'DW_TAG_GNU_formal_parameter_pack': DW_TAG_GNU_formal_parameter_pack,
        'DW_TAG_APPLE_Property': DW_TAG_APPLE_Property
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)

    def is_null(self):
        return self.get_enum_value() == 0

    def is_type(self):
        '''Return true if the tag represents a type'''
        return tag_is_type(self.get_enum_value())

    @classmethod
    def max_width(cls):
        max_key_len = 0
        for key in cls.enum:
            key_len = len(key)
            if key_len > max_key_len:
                max_key_len = key_len
        return max_key_len


class Attribute(dict_utils.Enum):
    enum = {
        'DW_AT_sibling': DW_AT_sibling,
        'DW_AT_location': DW_AT_location,
        'DW_AT_name': DW_AT_name,
        'DW_AT_ordering': DW_AT_ordering,
        'DW_AT_byte_size': DW_AT_byte_size,
        'DW_AT_bit_offset': DW_AT_bit_offset,
        'DW_AT_bit_size': DW_AT_bit_size,
        'DW_AT_stmt_list': DW_AT_stmt_list,
        'DW_AT_low_pc': DW_AT_low_pc,
        'DW_AT_high_pc': DW_AT_high_pc,
        'DW_AT_language': DW_AT_language,
        'DW_AT_discr': DW_AT_discr,
        'DW_AT_discr_value': DW_AT_discr_value,
        'DW_AT_visibility': DW_AT_visibility,
        'DW_AT_import': DW_AT_import,
        'DW_AT_string_length': DW_AT_string_length,
        'DW_AT_common_reference': DW_AT_common_reference,
        'DW_AT_comp_dir': DW_AT_comp_dir,
        'DW_AT_const_value': DW_AT_const_value,
        'DW_AT_containing_type': DW_AT_containing_type,
        'DW_AT_default_value': DW_AT_default_value,
        'DW_AT_inline': DW_AT_inline,
        'DW_AT_is_optional': DW_AT_is_optional,
        'DW_AT_lower_bound': DW_AT_lower_bound,
        'DW_AT_producer': DW_AT_producer,
        'DW_AT_prototyped': DW_AT_prototyped,
        'DW_AT_return_addr': DW_AT_return_addr,
        'DW_AT_start_scope': DW_AT_start_scope,
        'DW_AT_bit_stride': DW_AT_bit_stride,
        'DW_AT_upper_bound': DW_AT_upper_bound,
        'DW_AT_abstract_origin': DW_AT_abstract_origin,
        'DW_AT_accessibility': DW_AT_accessibility,
        'DW_AT_address_class': DW_AT_address_class,
        'DW_AT_artificial': DW_AT_artificial,
        'DW_AT_base_types': DW_AT_base_types,
        'DW_AT_calling_convention': DW_AT_calling_convention,
        'DW_AT_count': DW_AT_count,
        'DW_AT_data_member_location': DW_AT_data_member_location,
        'DW_AT_decl_column': DW_AT_decl_column,
        'DW_AT_decl_file': DW_AT_decl_file,
        'DW_AT_decl_line': DW_AT_decl_line,
        'DW_AT_declaration': DW_AT_declaration,
        'DW_AT_discr_list': DW_AT_discr_list,
        'DW_AT_encoding': DW_AT_encoding,
        'DW_AT_external': DW_AT_external,
        'DW_AT_frame_base': DW_AT_frame_base,
        'DW_AT_friend': DW_AT_friend,
        'DW_AT_identifier_case': DW_AT_identifier_case,
        'DW_AT_macro_info': DW_AT_macro_info,
        'DW_AT_namelist_item': DW_AT_namelist_item,
        'DW_AT_priority': DW_AT_priority,
        'DW_AT_segment': DW_AT_segment,
        'DW_AT_specification': DW_AT_specification,
        'DW_AT_static_link': DW_AT_static_link,
        'DW_AT_type': DW_AT_type,
        'DW_AT_use_location': DW_AT_use_location,
        'DW_AT_variable_parameter': DW_AT_variable_parameter,
        'DW_AT_virtuality': DW_AT_virtuality,
        'DW_AT_vtable_elem_location': DW_AT_vtable_elem_location,
        'DW_AT_allocated': DW_AT_allocated,
        'DW_AT_associated': DW_AT_associated,
        'DW_AT_data_location': DW_AT_data_location,
        'DW_AT_byte_stride': DW_AT_byte_stride,
        'DW_AT_entry_pc': DW_AT_entry_pc,
        'DW_AT_use_UTF8': DW_AT_use_UTF8,
        'DW_AT_extension': DW_AT_extension,
        'DW_AT_ranges': DW_AT_ranges,
        'DW_AT_trampoline': DW_AT_trampoline,
        'DW_AT_call_column': DW_AT_call_column,
        'DW_AT_call_file': DW_AT_call_file,
        'DW_AT_call_line': DW_AT_call_line,
        'DW_AT_description': DW_AT_description,
        'DW_AT_binary_scale': DW_AT_binary_scale,
        'DW_AT_decimal_scale': DW_AT_decimal_scale,
        'DW_AT_small': DW_AT_small,
        'DW_AT_decimal_sign': DW_AT_decimal_sign,
        'DW_AT_digit_count': DW_AT_digit_count,
        'DW_AT_picture_string': DW_AT_picture_string,
        'DW_AT_mutable': DW_AT_mutable,
        'DW_AT_threads_scaled': DW_AT_threads_scaled,
        'DW_AT_explicit': DW_AT_explicit,
        'DW_AT_object_pointer': DW_AT_object_pointer,
        'DW_AT_endianity': DW_AT_endianity,
        'DW_AT_elemental': DW_AT_elemental,
        'DW_AT_pure': DW_AT_pure,
        'DW_AT_recursive': DW_AT_recursive,
        'DW_AT_signature': DW_AT_signature,
        'DW_AT_main_subprogram': DW_AT_main_subprogram,
        'DW_AT_data_bit_offset': DW_AT_data_bit_offset,
        'DW_AT_const_expr': DW_AT_const_expr,
        'DW_AT_enum_class': DW_AT_enum_class,
        'DW_AT_linkage_name': DW_AT_linkage_name,
        'DW_AT_string_length_bit_size': DW_AT_string_length_bit_size,
        'DW_AT_string_length_byte_size': DW_AT_string_length_byte_size,
        'DW_AT_rank': DW_AT_rank,
        'DW_AT_str_offsets_base': DW_AT_str_offsets_base,
        'DW_AT_addr_base': DW_AT_addr_base,
        'DW_AT_ranges_base': DW_AT_ranges_base,
        'DW_AT_dwo_id': DW_AT_dwo_id,
        'DW_AT_dwo_name': DW_AT_dwo_name,
        'DW_AT_reference': DW_AT_reference,
        'DW_AT_rvalue_reference': DW_AT_rvalue_reference,
        'DW_AT_MIPS_fde': DW_AT_MIPS_fde,
        'DW_AT_MIPS_loop_begin': DW_AT_MIPS_loop_begin,
        'DW_AT_MIPS_tail_loop_begin': DW_AT_MIPS_tail_loop_begin,
        'DW_AT_MIPS_epilog_begin': DW_AT_MIPS_epilog_begin,
        'DW_AT_MIPS_loop_unroll_factor': DW_AT_MIPS_loop_unroll_factor,
        'DW_AT_MIPS_software_pipeline_depth':
            DW_AT_MIPS_software_pipeline_depth,
        'DW_AT_MIPS_linkage_name': DW_AT_MIPS_linkage_name,
        'DW_AT_MIPS_stride': DW_AT_MIPS_stride,
        'DW_AT_MIPS_abstract_name': DW_AT_MIPS_abstract_name,
        'DW_AT_MIPS_clone_origin': DW_AT_MIPS_clone_origin,
        'DW_AT_MIPS_has_inlines': DW_AT_MIPS_has_inlines,
        'DW_AT_MIPS_stride_byte': DW_AT_MIPS_stride_byte,
        'DW_AT_MIPS_stride_elem': DW_AT_MIPS_stride_elem,
        'DW_AT_MIPS_ptr_dopetype': DW_AT_MIPS_ptr_dopetype,
        'DW_AT_MIPS_allocatable_dopetype': DW_AT_MIPS_allocatable_dopetype,
        'DW_AT_MIPS_assumed_shape_dopetype': DW_AT_MIPS_assumed_shape_dopetype,
        'DW_AT_MIPS_assumed_size': DW_AT_MIPS_assumed_size,
        'DW_AT_sf_names': DW_AT_sf_names,
        'DW_AT_src_info': DW_AT_src_info,
        'DW_AT_mac_info': DW_AT_mac_info,
        'DW_AT_src_coords': DW_AT_src_coords,
        'DW_AT_body_begin': DW_AT_body_begin,
        'DW_AT_body_end': DW_AT_body_end,
        'DW_AT_GNU_vector': DW_AT_GNU_vector,
        'DW_AT_GNU_odr_signature': DW_AT_GNU_odr_signature,
        'DW_AT_GNU_template_name': DW_AT_GNU_template_name,
        'DW_AT_GNU_all_tail_call_sites': DW_AT_GNU_all_tail_call_sites,
        'DW_AT_APPLE_repository_file': DW_AT_APPLE_repository_file,
        'DW_AT_APPLE_repository_type': DW_AT_APPLE_repository_type,
        'DW_AT_APPLE_repository_name': DW_AT_APPLE_repository_name,
        'DW_AT_APPLE_repository_specification':
            DW_AT_APPLE_repository_specification,
        'DW_AT_APPLE_repository_import': DW_AT_APPLE_repository_import,
        'DW_AT_APPLE_repository_abstract_origin':
            DW_AT_APPLE_repository_abstract_origin,
        'DW_AT_APPLE_optimized': DW_AT_APPLE_optimized,
        'DW_AT_APPLE_flags': DW_AT_APPLE_flags,
        'DW_AT_APPLE_isa': DW_AT_APPLE_isa,
        'DW_AT_APPLE_block': DW_AT_APPLE_block,
        'DW_AT_APPLE_major_runtime_vers': DW_AT_APPLE_major_runtime_vers,
        'DW_AT_APPLE_runtime_class': DW_AT_APPLE_runtime_class,
        'DW_AT_APPLE_omit_frame_ptr': DW_AT_APPLE_omit_frame_ptr,
        'DW_AT_APPLE_property_name': DW_AT_APPLE_property_name,
        'DW_AT_APPLE_property_getter': DW_AT_APPLE_property_getter,
        'DW_AT_APPLE_property_setter': DW_AT_APPLE_property_setter,
        'DW_AT_APPLE_property_attribute': DW_AT_APPLE_property_attribute,
        'DW_AT_APPLE_objc_complete_type': DW_AT_APPLE_objc_complete_type,
        'DW_AT_APPLE_property': DW_AT_APPLE_property,
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)

    @classmethod
    def max_width(cls):
        max_key_len = 0
        for key in cls.enum:
            key_len = len(key)
            if key_len > max_key_len:
                max_key_len = key_len
        return max_key_len


class DW_ATE(dict_utils.Enum):
    enum = {
        'DW_ATE_address': DW_ATE_address,
        'DW_ATE_boolean': DW_ATE_boolean,
        'DW_ATE_complex_float': DW_ATE_complex_float,
        'DW_ATE_float': DW_ATE_float,
        'DW_ATE_signed': DW_ATE_signed,
        'DW_ATE_signed_char': DW_ATE_signed_char,
        'DW_ATE_unsigned': DW_ATE_unsigned,
        'DW_ATE_unsigned_char': DW_ATE_unsigned_char,
        'DW_ATE_imaginary_float': DW_ATE_imaginary_float,
        'DW_ATE_packed_decimal': DW_ATE_packed_decimal,
        'DW_ATE_numeric_string': DW_ATE_numeric_string,
        'DW_ATE_edited': DW_ATE_edited,
        'DW_ATE_signed_fixed': DW_ATE_signed_fixed,
        'DW_ATE_unsigned_fixed': DW_ATE_unsigned_fixed,
        'DW_ATE_decimal_float': DW_ATE_decimal_float,
        'DW_ATE_UTF': DW_ATE_UTF,
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)


class DW_VIRTUALITY(dict_utils.Enum):
    enum = {
        'DW_VIRTUALITY_none': DW_VIRTUALITY_none,
        'DW_VIRTUALITY_virtual': DW_VIRTUALITY_virtual,
        'DW_VIRTUALITY_pure_virtual': DW_VIRTUALITY_pure_virtual
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)


class DW_ACCESS(dict_utils.Enum):
    enum = {
        'DW_ACCESS_public': DW_ACCESS_public,
        'DW_ACCESS_protected': DW_ACCESS_protected,
        'DW_ACCESS_private': DW_ACCESS_private
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)


class Operand(object):
    def __init__(self, op, num_values=0, value1=0, value2=0):
        self.op = op
        self.num_values = num_values
        self.value1 = value1
        self.value2 = value2

    def dump(self, verbose, f=sys.stdout):
        if self.num_values == 0:
            print >>f, '%s' % (self.op),
        elif self.num_values == 1:
            if self.op in [DW_OP_addr]:
                print >>f, '%s(0x%16.16x)' % (self.op, self.value1),
            else:
                print >>f, '%s(%u)' % (self.op, self.value1),
        elif self.num_values == 2:
            print >>f, '%s(%s, %s)' % (self.op, self.value1, self.value2),
        else:
            print >>f, 'error: unhandled argument count in Operand class'
            raise ValueError

    def __str__(self):
        output = StringIO.StringIO()
        self.dump(True, output)
        return output.getvalue()


DW_STACK_TYPE_FILE_ADDR = 1
DW_STACK_TYPE_LOAD_ADDR = 2
DW_STACK_TYPE_SCALAR = 3


class LocationValue(object):
    def __init__(self, value, type):
        self.value = value
        self.type = type


class Location(object):
    def __init__(self, die, attr_value):
        self.die = die
        self.attr_value = attr_value
        self.operands = None

    def has_file_address(self):
        operands = self.get_operands()
        for operand in operands:
            if operand.op.get_enum_value() == DW_OP_addr:
                return True
        return False

    def evaluate(self, parent_value=None, address=-1):
        operands = self.get_operands()
        stack = list()
        for operand in operands:
            op = operand.op.get_enum_value()
            if op == DW_OP_addr:
                stack.append(LocationValue(operand.value1,
                                           DW_STACK_TYPE_FILE_ADDR))
            elif op in [DW_OP_constu,
                        DW_OP_const1u,
                        DW_OP_const2u,
                        DW_OP_const4u,
                        DW_OP_const8u,
                        DW_OP_consts,
                        DW_OP_const1s,
                        DW_OP_const2s,
                        DW_OP_const4s,
                        DW_OP_const8s]:
                stack.append(LocationValue(operand.value1,
                                           DW_STACK_TYPE_SCALAR))
            elif op == DW_OP_plus:
                if len(stack) < 2:
                    print 'error: stack size is too small for DW_OP_plus in',
                    print self
                    exit(2)
                else:
                    last = stack.pop()
                    stack[-1].value = stack[-1].value + last.value
            elif op == DW_OP_minus:
                if len(stack) < 2:
                    print 'error: stack size is too small for DW_OP_plus in',
                    print self
                    exit(2)
                else:
                    last = stack.pop()
                    stack[-1].value = stack[-1].value - last.value
            else:
                print 'error: unhandled %s' % (operand.op)
                return None
        stack_len = len(stack)
        if stack_len == 1:
            return stack[-1]
        if stack_len == 0:
            print 'error: nothing left of the stack for location: %s' % (self)
        if stack_len != 1:
            print 'error: multiple things left on the stack for location:',
            print self
        return None

    def get_operands(self):
        if self.operands is None:
            self.operands = list()
            if self.attr_value.attr_spec.form.is_block():
                data = file_extract.FileExtract(
                        StringIO.StringIO(self.attr_value.value),
                        self.die.cu.data.byte_order,
                        self.die.cu.data.addr_size)
                op = data.get_uint8()
                while op:
                    op_enum = DW_OP(op)
                    if op in [DW_OP_addr, DW_OP_call_ref]:
                        # Opcodes with a single address sized argument
                        value = data.get_address()
                        self.operands.append(Operand(op_enum, 1, value))
                    elif op == DW_OP_const1s:
                        self.operands.append(Operand(op_enum, 1,
                                                     data.get_sint8()))
                    elif op == DW_OP_const2s:
                        self.operands.append(Operand(op_enum, 1,
                                                     data.get_sint16()))
                    elif op == DW_OP_const4s:
                        self.operands.append(Operand(op_enum, 1,
                                                     data.get_sint32()))
                    elif op == DW_OP_const8s:
                        self.operands.append(Operand(op_enum, 1,
                                                     data.get_sint64()))
                    elif op in [DW_OP_const1u, DW_OP_const1s, DW_OP_pick,
                                DW_OP_deref_size, DW_OP_xderef_size]:
                        # Opcodes with a single 1 byte argument
                        self.operands.append(Operand(op_enum, 1,
                                                     data.get_uint8()))
                    elif op in [DW_OP_const2u, DW_OP_skip, DW_OP_bra,
                                DW_OP_call2]:
                        # Opcodes with a single 2 byte argument
                        self.operands.append(Operand(op_enum, 1,
                                             data.get_uint16()))
                    elif op in [DW_OP_const4u, DW_OP_call4]:
                        # Opcodes with a single 4 byte argument
                        self.operands.append(Operand(op_enum, 1,
                                                     data.get_uint32()))
                    elif op == DW_OP_const8u:
                        # Opcodes with a single 8 byte argument
                        self.operands.append(Operand(op_enum, 1,
                                                     data.get_uint64()))
                    elif op in [DW_OP_consts,
                                DW_OP_breg0,
                                DW_OP_breg1,
                                DW_OP_breg2,
                                DW_OP_breg3,
                                DW_OP_breg4,
                                DW_OP_breg5,
                                DW_OP_breg6,
                                DW_OP_breg7,
                                DW_OP_breg8,
                                DW_OP_breg9,
                                DW_OP_breg10,
                                DW_OP_breg11,
                                DW_OP_breg12,
                                DW_OP_breg13,
                                DW_OP_breg14,
                                DW_OP_breg15,
                                DW_OP_breg16,
                                DW_OP_breg17,
                                DW_OP_breg18,
                                DW_OP_breg19,
                                DW_OP_breg20,
                                DW_OP_breg21,
                                DW_OP_breg22,
                                DW_OP_breg23,
                                DW_OP_breg24,
                                DW_OP_breg25,
                                DW_OP_breg26,
                                DW_OP_breg27,
                                DW_OP_breg28,
                                DW_OP_breg29,
                                DW_OP_breg30,
                                DW_OP_breg31,
                                DW_OP_fbreg]:
                        # Opcodes with a 1 sleb128 byte argument
                        value = data.get_sleb128()
                        self.operands.append(Operand(op_enum, 1, value))
                    elif op in [DW_OP_constu,
                                DW_OP_plus_uconst,
                                DW_OP_regx,
                                DW_OP_piece]:
                        # Opcodes with a 1 uleb128 byte argument
                        value = data.get_uleb128()
                        self.operands.append(Operand(op_enum, 1, value))
                    elif op in [DW_OP_bregx, DW_OP_bit_piece]:
                        # Opcodes with a 2 uleb128 byte argument
                        value1 = data.get_uleb128()
                        value2 = data.get_uleb128()
                        self.operands.append(Operand(op_enum, 2, value1,
                                                     value2))
                    elif op == DW_OP_implicit_value:
                        # Opcodes with a a uleb128 length + block data
                        block_len = data.get_uleb128()
                        block = data.read_size(block_len)
                        self.operands.append(Operand(op_enum, 1, block))
                    else:
                        self.operands.append(Operand(op_enum))
                    op = data.get_uleb128()
        return self.operands

    def dump(self, verbose, f=sys.stdout):
        operands = self.get_operands()
        if operands:
            for (idx, operand) in enumerate(operands):
                if idx > 0:
                    print >>f, ',',
                operand.dump(verbose=verbose, f=f)

    def __str__(self):
        output = StringIO.StringIO()
        self.dump(True, output)
        return output.getvalue()


class DW_OP(dict_utils.Enum):
    enum = {
        'DW_OP_addr': DW_OP_addr,
        'DW_OP_deref': DW_OP_deref,
        'DW_OP_const1u': DW_OP_const1u,
        'DW_OP_const1s': DW_OP_const1s,
        'DW_OP_const2u': DW_OP_const2u,
        'DW_OP_const2s': DW_OP_const2s,
        'DW_OP_const4u': DW_OP_const4u,
        'DW_OP_const4s': DW_OP_const4s,
        'DW_OP_const8u': DW_OP_const8u,
        'DW_OP_const8s': DW_OP_const8s,
        'DW_OP_constu': DW_OP_constu,
        'DW_OP_consts': DW_OP_consts,
        'DW_OP_dup': DW_OP_dup,
        'DW_OP_drop': DW_OP_drop,
        'DW_OP_over': DW_OP_over,
        'DW_OP_pick': DW_OP_pick,
        'DW_OP_swap': DW_OP_swap,
        'DW_OP_rot': DW_OP_rot,
        'DW_OP_xderef': DW_OP_xderef,
        'DW_OP_abs': DW_OP_abs,
        'DW_OP_and': DW_OP_and,
        'DW_OP_div': DW_OP_div,
        'DW_OP_minus': DW_OP_minus,
        'DW_OP_mod': DW_OP_mod,
        'DW_OP_mul': DW_OP_mul,
        'DW_OP_neg': DW_OP_neg,
        'DW_OP_not': DW_OP_not,
        'DW_OP_or': DW_OP_or,
        'DW_OP_plus': DW_OP_plus,
        'DW_OP_plus_uconst': DW_OP_plus_uconst,
        'DW_OP_shl': DW_OP_shl,
        'DW_OP_shr': DW_OP_shr,
        'DW_OP_shra': DW_OP_shra,
        'DW_OP_xor': DW_OP_xor,
        'DW_OP_skip': DW_OP_skip,
        'DW_OP_bra': DW_OP_bra,
        'DW_OP_eq': DW_OP_eq,
        'DW_OP_ge': DW_OP_ge,
        'DW_OP_gt': DW_OP_gt,
        'DW_OP_le': DW_OP_le,
        'DW_OP_lt': DW_OP_lt,
        'DW_OP_ne': DW_OP_ne,
        'DW_OP_lit0': DW_OP_lit0,
        'DW_OP_lit1': DW_OP_lit1,
        'DW_OP_lit2': DW_OP_lit2,
        'DW_OP_lit3': DW_OP_lit3,
        'DW_OP_lit4': DW_OP_lit4,
        'DW_OP_lit5': DW_OP_lit5,
        'DW_OP_lit6': DW_OP_lit6,
        'DW_OP_lit7': DW_OP_lit7,
        'DW_OP_lit8': DW_OP_lit8,
        'DW_OP_lit9': DW_OP_lit9,
        'DW_OP_lit10': DW_OP_lit10,
        'DW_OP_lit11': DW_OP_lit11,
        'DW_OP_lit12': DW_OP_lit12,
        'DW_OP_lit13': DW_OP_lit13,
        'DW_OP_lit14': DW_OP_lit14,
        'DW_OP_lit15': DW_OP_lit15,
        'DW_OP_lit16': DW_OP_lit16,
        'DW_OP_lit17': DW_OP_lit17,
        'DW_OP_lit18': DW_OP_lit18,
        'DW_OP_lit19': DW_OP_lit19,
        'DW_OP_lit20': DW_OP_lit20,
        'DW_OP_lit21': DW_OP_lit21,
        'DW_OP_lit22': DW_OP_lit22,
        'DW_OP_lit23': DW_OP_lit23,
        'DW_OP_lit24': DW_OP_lit24,
        'DW_OP_lit25': DW_OP_lit25,
        'DW_OP_lit26': DW_OP_lit26,
        'DW_OP_lit27': DW_OP_lit27,
        'DW_OP_lit28': DW_OP_lit28,
        'DW_OP_lit29': DW_OP_lit29,
        'DW_OP_lit30': DW_OP_lit30,
        'DW_OP_lit31': DW_OP_lit31,
        'DW_OP_reg0': DW_OP_reg0,
        'DW_OP_reg1': DW_OP_reg1,
        'DW_OP_reg2': DW_OP_reg2,
        'DW_OP_reg3': DW_OP_reg3,
        'DW_OP_reg4': DW_OP_reg4,
        'DW_OP_reg5': DW_OP_reg5,
        'DW_OP_reg6': DW_OP_reg6,
        'DW_OP_reg7': DW_OP_reg7,
        'DW_OP_reg8': DW_OP_reg8,
        'DW_OP_reg9': DW_OP_reg9,
        'DW_OP_reg10': DW_OP_reg10,
        'DW_OP_reg11': DW_OP_reg11,
        'DW_OP_reg12': DW_OP_reg12,
        'DW_OP_reg13': DW_OP_reg13,
        'DW_OP_reg14': DW_OP_reg14,
        'DW_OP_reg15': DW_OP_reg15,
        'DW_OP_reg16': DW_OP_reg16,
        'DW_OP_reg17': DW_OP_reg17,
        'DW_OP_reg18': DW_OP_reg18,
        'DW_OP_reg19': DW_OP_reg19,
        'DW_OP_reg20': DW_OP_reg20,
        'DW_OP_reg21': DW_OP_reg21,
        'DW_OP_reg22': DW_OP_reg22,
        'DW_OP_reg23': DW_OP_reg23,
        'DW_OP_reg24': DW_OP_reg24,
        'DW_OP_reg25': DW_OP_reg25,
        'DW_OP_reg26': DW_OP_reg26,
        'DW_OP_reg27': DW_OP_reg27,
        'DW_OP_reg28': DW_OP_reg28,
        'DW_OP_reg29': DW_OP_reg29,
        'DW_OP_reg30': DW_OP_reg30,
        'DW_OP_reg31': DW_OP_reg31,
        'DW_OP_breg0': DW_OP_breg0,
        'DW_OP_breg1': DW_OP_breg1,
        'DW_OP_breg2': DW_OP_breg2,
        'DW_OP_breg3': DW_OP_breg3,
        'DW_OP_breg4': DW_OP_breg4,
        'DW_OP_breg5': DW_OP_breg5,
        'DW_OP_breg6': DW_OP_breg6,
        'DW_OP_breg7': DW_OP_breg7,
        'DW_OP_breg8': DW_OP_breg8,
        'DW_OP_breg9': DW_OP_breg9,
        'DW_OP_breg10': DW_OP_breg10,
        'DW_OP_breg11': DW_OP_breg11,
        'DW_OP_breg12': DW_OP_breg12,
        'DW_OP_breg13': DW_OP_breg13,
        'DW_OP_breg14': DW_OP_breg14,
        'DW_OP_breg15': DW_OP_breg15,
        'DW_OP_breg16': DW_OP_breg16,
        'DW_OP_breg17': DW_OP_breg17,
        'DW_OP_breg18': DW_OP_breg18,
        'DW_OP_breg19': DW_OP_breg19,
        'DW_OP_breg20': DW_OP_breg20,
        'DW_OP_breg21': DW_OP_breg21,
        'DW_OP_breg22': DW_OP_breg22,
        'DW_OP_breg23': DW_OP_breg23,
        'DW_OP_breg24': DW_OP_breg24,
        'DW_OP_breg25': DW_OP_breg25,
        'DW_OP_breg26': DW_OP_breg26,
        'DW_OP_breg27': DW_OP_breg27,
        'DW_OP_breg28': DW_OP_breg28,
        'DW_OP_breg29': DW_OP_breg29,
        'DW_OP_breg30': DW_OP_breg30,
        'DW_OP_breg31': DW_OP_breg31,
        'DW_OP_regx': DW_OP_regx,
        'DW_OP_fbreg': DW_OP_fbreg,
        'DW_OP_bregx': DW_OP_bregx,
        'DW_OP_piece': DW_OP_piece,
        'DW_OP_deref_size': DW_OP_deref_size,
        'DW_OP_xderef_size': DW_OP_xderef_size,
        'DW_OP_nop': DW_OP_nop,
        'DW_OP_push_object_address': DW_OP_push_object_address,
        'DW_OP_call2': DW_OP_call2,
        'DW_OP_call4': DW_OP_call4,
        'DW_OP_call_ref': DW_OP_call_ref,
        'DW_OP_form_tls_address': DW_OP_form_tls_address,
        'DW_OP_call_frame_cfa': DW_OP_call_frame_cfa,
        'DW_OP_bit_piece': DW_OP_bit_piece,
        'DW_OP_implicit_value': DW_OP_implicit_value,
        'DW_OP_stack_value': DW_OP_stack_value,
        'DW_OP_lo_user': DW_OP_lo_user,
        'DW_OP_GNU_push_tls_address': DW_OP_GNU_push_tls_address,
        'DW_OP_APPLE_uninit': DW_OP_APPLE_uninit,
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)


class DW_LANG(dict_utils.Enum):
    enum = {
        'DW_LANG_C89': DW_LANG_C89,
        'DW_LANG_C': DW_LANG_C,
        'DW_LANG_Ada83': DW_LANG_Ada83,
        'DW_LANG_C_plus_plus': DW_LANG_C_plus_plus,
        'DW_LANG_Cobol74': DW_LANG_Cobol74,
        'DW_LANG_Cobol85': DW_LANG_Cobol85,
        'DW_LANG_Fortran77': DW_LANG_Fortran77,
        'DW_LANG_Fortran90': DW_LANG_Fortran90,
        'DW_LANG_Pascal83': DW_LANG_Pascal83,
        'DW_LANG_Modula2': DW_LANG_Modula2,
        'DW_LANG_Java': DW_LANG_Java,
        'DW_LANG_C99': DW_LANG_C99,
        'DW_LANG_Ada95': DW_LANG_Ada95,
        'DW_LANG_Fortran95': DW_LANG_Fortran95,
        'DW_LANG_PLI': DW_LANG_PLI,
        'DW_LANG_ObjC': DW_LANG_ObjC,
        'DW_LANG_ObjC_plus_plus': DW_LANG_ObjC_plus_plus,
        'DW_LANG_UPC': DW_LANG_UPC,
        'DW_LANG_D': DW_LANG_D,
        'DW_LANG_Python': DW_LANG_Python,
        'DW_LANG_OpenCL': DW_LANG_OpenCL,
        'DW_LANG_Go': DW_LANG_Go,
        'DW_LANG_Modula3': DW_LANG_Modula3,
        'DW_LANG_Haskell': DW_LANG_Haskell,
        'DW_LANG_C_plus_plus_03': DW_LANG_C_plus_plus_03,
        'DW_LANG_C_plus_plus_11': DW_LANG_C_plus_plus_11,
        'DW_LANG_OCaml': DW_LANG_OCaml,
        'DW_LANG_Rust': DW_LANG_Rust,
        'DW_LANG_C11': DW_LANG_C11,
        'DW_LANG_Swift': DW_LANG_Swift,
        'DW_LANG_Julia': DW_LANG_Julia,
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)


class DW_LNS(dict_utils.Enum):
    enum = {
        'DW_LNS_copy': DW_LNS_copy,
        'DW_LNS_advance_pc': DW_LNS_advance_pc,
        'DW_LNS_advance_line': DW_LNS_advance_line,
        'DW_LNS_set_file': DW_LNS_set_file,
        'DW_LNS_set_column': DW_LNS_set_column,
        'DW_LNS_negate_stmt': DW_LNS_negate_stmt,
        'DW_LNS_set_basic_block': DW_LNS_set_basic_block,
        'DW_LNS_const_add_pc': DW_LNS_const_add_pc,
        'DW_LNS_fixed_advance_pc': DW_LNS_fixed_advance_pc,
        'DW_LNS_set_prologue_end': DW_LNS_set_prologue_end,
        'DW_LNS_set_epilogue_begin': DW_LNS_set_epilogue_begin,
        'DW_LNS_set_isa': DW_LNS_set_isa,
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)

    @classmethod
    def max_width(cls):
        max_key_len = 0
        for key in cls.enum:
            key_len = len(key)
            if key_len > max_key_len:
                max_key_len = key_len
        return max_key_len


class DW_LNE(dict_utils.Enum):
    enum = {
        'DW_LNE_end_sequence': DW_LNE_end_sequence,
        'DW_LNE_set_address': DW_LNE_set_address,
        'DW_LNE_define_file': DW_LNE_define_file,
        'DW_LNE_set_discriminator': DW_LNE_set_discriminator,
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)

    @classmethod
    def max_width(cls):
        max_key_len = 0
        for key in cls.enum:
            key_len = len(key)
            if key_len > max_key_len:
                max_key_len = key_len
        return max_key_len


class DW_INL(dict_utils.Enum):
    enum = {
        'DW_INL_not_inlined': DW_INL_not_inlined,
        'DW_INL_inlined': DW_INL_inlined,
        'DW_INL_declared_not_inlined': DW_INL_declared_not_inlined,
        'DW_INL_declared_inlined': DW_INL_declared_inlined
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)


class Form(dict_utils.Enum):
    enum = {
        'DW_FORM_addr': DW_FORM_addr,
        'DW_FORM_block2': DW_FORM_block2,
        'DW_FORM_block4': DW_FORM_block4,
        'DW_FORM_data2': DW_FORM_data2,
        'DW_FORM_data4': DW_FORM_data4,
        'DW_FORM_data8': DW_FORM_data8,
        'DW_FORM_string': DW_FORM_string,
        'DW_FORM_block': DW_FORM_block,
        'DW_FORM_block1': DW_FORM_block1,
        'DW_FORM_data1': DW_FORM_data1,
        'DW_FORM_flag': DW_FORM_flag,
        'DW_FORM_sdata': DW_FORM_sdata,
        'DW_FORM_strp': DW_FORM_strp,
        'DW_FORM_udata': DW_FORM_udata,
        'DW_FORM_ref_addr': DW_FORM_ref_addr,
        'DW_FORM_ref1': DW_FORM_ref1,
        'DW_FORM_ref2': DW_FORM_ref2,
        'DW_FORM_ref4': DW_FORM_ref4,
        'DW_FORM_ref8': DW_FORM_ref8,
        'DW_FORM_ref_udata': DW_FORM_ref_udata,
        'DW_FORM_indirect': DW_FORM_indirect,
        'DW_FORM_sec_offset': DW_FORM_sec_offset,
        'DW_FORM_exprloc': DW_FORM_exprloc,
        'DW_FORM_flag_present': DW_FORM_flag_present,
        'DW_FORM_ref_sig8': DW_FORM_ref_sig8,
        'DW_FORM_GNU_addr_index': DW_FORM_GNU_addr_index,
        'DW_FORM_GNU_str_index': DW_FORM_GNU_str_index,
    }

    def __init__(self, initial_value=0):
        dict_utils.Enum.__init__(self, initial_value, self.enum)

    @classmethod
    def max_width(cls):
        max_key_len = 0
        for key in cls.enum:
            key_len = len(key)
            if key_len > max_key_len:
                max_key_len = key_len
        return max_key_len

    def is_block(self):
        form = self.get_enum_value()
        if (form == DW_FORM_block1 or form == DW_FORM_block2 or
                form == DW_FORM_block4 or form == DW_FORM_block or
                form == DW_FORM_exprloc):
            return True
        else:
            return False

    def is_address(self):
        return self.get_enum_value() == DW_FORM_addr

    def is_reference(self):
        form = self.get_enum_value()
        if (form == DW_FORM_ref1 or form == DW_FORM_ref2 or
                form == DW_FORM_ref4 or form == DW_FORM_ref8 or
                form == DW_FORM_ref_udata or form == DW_FORM_ref_addr):
            return True
        else:
            return False

    def get_fixed_size(self, dwarf_info=None):
        form = self.get_enum_value()
        if form == DW_FORM_strp:
            return 4
        elif form == DW_FORM_addr:
            if dwarf_info:
                return dwarf_info.addr_size
            else:
                # Not fixed unless we know our compile unit since it is an
                # address sized object
                return -1
        elif form == DW_FORM_data1:
            return 1
        elif form == DW_FORM_data2:
            return 2
        elif form == DW_FORM_data4:
            return 4
        elif form == DW_FORM_data8:
            return 8
        elif form == DW_FORM_udata:
            return -1  # Not fixed size
        elif form == DW_FORM_sdata:
            return -1  # Not fixed size
        elif form == DW_FORM_string:
            return -1  # Not fixed size
        elif form == DW_FORM_block1:
            return -1  # Not fixed size
        elif form == DW_FORM_block2:
            return -1  # Not fixed size
        elif form == DW_FORM_block4:
            return -1  # Not fixed size
        elif form == DW_FORM_block:
            return -1  # Not fixed size
        elif form == DW_FORM_exprloc:
            return -1  # Not fixed size
        elif form == DW_FORM_flag:
            return 1
        elif form == DW_FORM_ref1:
            return 1
        elif form == DW_FORM_ref2:
            return 2
        elif form == DW_FORM_ref4:
            return 4
        elif form == DW_FORM_ref8:
            return 8
        elif form == DW_FORM_ref_udata:
            return -1  # Not fixed size
        elif form == DW_FORM_flag_present:
            return 0
        elif form == DW_FORM_ref_sig8:
            return 8
        elif form == DW_FORM_ref_addr or form == DW_FORM_sec_offset:
            if dwarf_info:
                if dwarf_info.version <= 2:
                    return dwarf_info.addr_size
                else:
                    return dwarf_info.dwarf_size
            else:
                return -1
        elif form == DW_FORM_indirect:
            return -1
        return -1

    def get_byte_size(self, die, value):
        size = self.get_fixed_size(die.cu.dwarf_info)
        if size >= 0:
            return size
        form = self.get_enum_value()
        if form == DW_FORM_udata or form == DW_FORM_ref_udata:
            return get_uleb128_byte_size(value)
        elif form == DW_FORM_sdata:
            return get_uleb128_byte_size(value)
        elif form == DW_FORM_string:
            return len(value) + 1
        elif form == DW_FORM_indirect:
            # TODO: handle indirect form
            pass
        elif form == DW_FORM_block1:
            return 1 + len(value)
        elif form == DW_FORM_block2:
            return 2 + len(value)
        elif form == DW_FORM_block4:
            return 4 + len(value)
        elif form == DW_FORM_block:
            return get_uleb128_byte_size(len(value)) + len(value)
        elif form == DW_FORM_exprloc:
            return get_uleb128_byte_size(len(value)) + len(value)
        print 'error: failed to get byte size of form %s' % (self)
        raise ValueError

    def skip(self, die, data):
        size = self.get_fixed_size(die.cu.dwarf_info)
        if size == 0:
            return True
        if size < 0:
            form = self.get_enum_value()
            if form == DW_FORM_udata or form == DW_FORM_ref_udata:
                data.get_uleb128()
                return True
            elif form == DW_FORM_sdata:
                data.get_sleb128()
                return True
            elif form == DW_FORM_string:
                data.get_c_string()
                return True
            elif form == DW_FORM_indirect:
                indirect_form = Form(data.get_uleb128())
                return indirect_form.skip(die, data)
            elif form == DW_FORM_block1:
                size = data.get_uint8()
            elif form == DW_FORM_block2:
                size = data.get_uint16()
            elif form == DW_FORM_block4:
                size = data.get_uint32()
            elif form == DW_FORM_block:
                size = data.get_uleb128()
            elif form == DW_FORM_exprloc:
                size = data.get_uleb128()
            else:
                print 'error: failed to skip form %s' % (self)
                return False
        if size > 0:
            data.seek(data.tell()+size)
        return True

    def extract_value(self, die, data, str_data):
        form = self.get_enum_value()
        block_len = -1
        if form == DW_FORM_strp:
            strp = data.get_uint32()
            str_data.seek(strp)
            return str_data.get_c_string()
        elif form == DW_FORM_addr:
            return data.get_address()
        elif form == DW_FORM_data1:
            return data.get_uint8()
        elif form == DW_FORM_data2:
            return data.get_uint16()
        elif form == DW_FORM_data4:
            return data.get_uint32()
        elif form == DW_FORM_data8:
            return data.get_uint64()
        elif form == DW_FORM_udata:
            return data.get_uleb128()
        elif form == DW_FORM_sdata:
            return data.get_sleb128()
        elif form == DW_FORM_string:
            return data.get_c_string()
        elif form == DW_FORM_block1:
            block_len = data.get_uint8()
        elif form == DW_FORM_block2:
            block_len = data.get_uint16()
        elif form == DW_FORM_block4:
            block_len = data.get_uint32()
        elif form == DW_FORM_block:
            block_len = data.get_uleb128()
        elif form == DW_FORM_exprloc:
            block_len = data.get_uleb128()
        elif form == DW_FORM_flag:
            return data.get_uint8()
        elif form == DW_FORM_ref1:
            return die.cu.offset + data.get_uint8()
        elif form == DW_FORM_ref2:
            return die.cu.offset + data.get_uint16()
        elif form == DW_FORM_ref4:
            return die.cu.offset + data.get_uint32()
        elif form == DW_FORM_ref8:
            return die.cu.offset + data.get_uint64()
        elif form == DW_FORM_ref_udata:
            return die.cu.offset + data.get_uleb128()
        elif form == DW_FORM_sec_offset:
            fixed_size = self.get_fixed_size(die.cu.dwarf_info)
            return data.get_uint_size(fixed_size, 0)
        elif form == DW_FORM_flag_present:
            return 1
        elif form == DW_FORM_ref_sig8:
            return data.get_uint64()
        elif form == DW_FORM_ref_addr:
            fixed_size = self.get_fixed_size(die.cu.dwarf_info)
            return data.get_uint_size(fixed_size, 0)
        elif form == DW_FORM_indirect:
            indirect_form = Form(data.get_uleb128())
            return indirect_form.extract_value(die, data, str_data)
        if block_len >= 0:
            return data.read_size(block_len)
        return None


def get_color_offset(offset):
    colorizer = term_colors.TerminalColors(enable_colors)
    return colorizer.yellow() + "%#8.8x" % (offset) + colorizer.reset()


def get_color_tag(attr):
    colorizer = term_colors.TerminalColors(enable_colors)
    return colorizer.blue() + str(attr) + colorizer.reset()


def get_color_attr(attr):
    colorizer = term_colors.TerminalColors(enable_colors)
    return colorizer.cyan() + str(attr) + colorizer.reset()


def get_color_form(form):
    colorizer = term_colors.TerminalColors(enable_colors)
    return colorizer.faint() + str(form) + colorizer.reset()


def get_color_string(s):
    colorizer = term_colors.TerminalColors(enable_colors)
    return colorizer.green() + s + colorizer.reset()


def get_color_DW_constant(c):
    colorizer = term_colors.TerminalColors(enable_colors)
    return colorizer.faint() + str(c) + colorizer.reset()


class AttributeSpec:
    def __init__(self, attr, form):
        self.attr = Attribute(attr)
        self.form = Form(form)

    def __str__(self):
        return '%-*s %s' % (Attribute.max_width(), get_color_attr(self.attr),
                            get_color_form(self.form))

    def __eq__(self, rhs):
        if rhs is None:
            return False
        return self.attr == rhs.attr and self.form == rhs.form

    def __ne__(self, rhs):
        if rhs is None:
            return True
        return self.attr != rhs.attr or self.form != rhs.form


class AttributeValue:
    def __init__(self, attr_spec):
        self.offset = 0
        self.attr_spec = attr_spec
        self.value = None

    def extract_value(self, die, data, str_data):
        self.offset = data.tell()
        self.value = self.attr_spec.form.extract_value(die, data, str_data)
        return self.value is not None

    def get_value(self, die):
        attr = self.attr_spec.attr.get_enum_value()
        if attr == DW_AT_language:
            return DW_LANG(self.value)
        if attr == DW_AT_encoding:
            return DW_ATE(self.value)
        if attr == DW_AT_virtuality:
            return DW_VIRTUALITY(self.value)
        if attr == DW_AT_accessibility:
            return DW_ACCESS(self.value)
        if attr == DW_AT_inline:
            return DW_INL(self.value)
        if attr in [DW_AT_frame_base, DW_AT_location,
                    DW_AT_data_member_location, DW_AT_vtable_elem_location,
                    DW_AT_data_location]:
            if die:
                return Location(die, self)
        return None

    def get_item_dictionary(self, die):
        return {'#0': '0x%8.8x' % (self.offset),
                'name': str(self.attr_spec.attr),
                'value': self.get_value_as_string(die),
                'children': False,
                'tree-item-delegate': self}

    # def get_child_item_dictionaries(self):
    #     item_dicts = list()
    #     child_dies = self.get_children()
    #     for die in child_dies:
    #         item_dicts.append(die.get_item_dictionary())
    #     return item_dicts

    def get_value_as_string(self, die=None):
        attr = self.attr_spec.attr.get_enum_value()
        if attr == DW_AT_decl_file or attr == DW_AT_call_file:
            if die:
                filename = die.cu.get_file(self.value)
                if filename:
                    return '"%s"' % (filename)
        elif attr == DW_AT_decl_line or attr == DW_AT_call_line:
            return '%u' % (self.value)
        elif die is not None and attr == DW_AT_ranges:
            return str(die.get_debug_ranges())
        enum_value = self.get_value(die)
        if enum_value:
            return str(enum_value)
        else:
            if self.attr_spec.form.is_block():
                output = StringIO.StringIO()
                dump_block(self.value, output)
                return '%s' % (output.getvalue())
            elif self.attr_spec.form.is_reference():
                return '{0x%8.8x}' % (self.value)
            elif is_string(self.value):
                return '"%s"' % (self.value)
            else:
                fixed_size = self.attr_spec.form.get_fixed_size(
                        die.cu.dwarf_info)
                if fixed_size >= 0:
                    if fixed_size == 1:
                        return '0x%2.2x' % (self.value)
                    elif fixed_size == 2:
                        return '0x%4.4x' % (self.value)
                    elif fixed_size == 4:
                        return '0x%8.8x' % (self.value)
                    elif fixed_size == 8:
                        return '0x%16.16x' % (self.value)
                    else:
                        return '0x%x' % (self.value)
                else:
                    return '0x%x' % (self.value)

    def dump(self, die, verbose, f=sys.stdout):
        if die:
            indent_level = die.depth
        else:
            indent_level = 0
        colorizer = term_colors.TerminalColors(enable_colors)
        form_value = self.get_value_as_string(die)
        offset_color = colorizer.yellow()
        attribute_color = colorizer.cyan()
        if self.attr_spec.form.is_reference():
            form_value_color = colorizer.yellow()
        elif form_value.startswith('"'):
            form_value_color = colorizer.green()
        elif form_value.startswith('DW_'):
            form_value_color = colorizer.faint()
        else:
            form_value_color = ''
        if verbose:
            f.write('%s0x%8.8x%s: %*s%s%-*s%s %-*s %s%s%s\n' % (offset_color,
                    self.offset, colorizer.reset(),
                    1 + indent_level * indent_width, '', attribute_color,
                    Attribute.max_width(), self.attr_spec.attr,
                    colorizer.reset(), Form.max_width(), self.attr_spec.form,
                    form_value_color, form_value, colorizer.reset()))
        else:
            f.write('%*s%s%s%s ( %s%s%s )\n' % (
                    13 + indent_level * indent_width, '', attribute_color,
                    self.attr_spec.attr, colorizer.reset(), form_value_color,
                    form_value, colorizer.reset()))

    def __str__(self):
        output = StringIO.StringIO()
        self.dump(die=None, verbose=True, f=output)
        return output.getvalue()


class AbbrevDecl:
    def __init__(self):
        self.offset = 0
        self.code = 0
        self.tag = 0
        self.has_children = False
        self.attribute_specs = list()
        self.fixed_size = -1
        self.fixed_addrs = 0

    def has_attributes(self):
        return len(self.attribute_specs) > 0

    def might_have_attribute(self, attr_enum_value):
        for attr_spec in self.attribute_specs:
            attr = attr_spec.attr.get_enum_value()
            if (attr == attr_enum_value or attr == DW_AT_specification or
                    attr == DW_AT_abstract_origin):
                return True
        return False

    def might_have_any_attributes(self, attr_enum_values):
        for attr_spec in self.attribute_specs:
            attr = attr_spec.attr.get_enum_value()
            if (attr in attr_enum_values or attr == DW_AT_specification or
                    attr == DW_AT_abstract_origin):
                return True
        return False

    def encode(self, encoder):
        self.offset = encoder.file.tell()
        encoder.put_uleb128(self.code)
        encoder.put_uleb128(self.tag)
        encoder.put_uint8(self.has_children)
        for attr_spec in self.attribute_specs:
            encoder.put_uleb128(attr_spec.attr.get_enum_value())
            encoder.put_uleb128(attr_spec.form.get_enum_value())
        encoder.put_uleb128(0)
        encoder.put_uleb128(0)

    def unpack(self, data):
        self.offset = data.tell()
        self.code = data.get_uleb128()
        if self.code != 0:
            self.tag = Tag(data.get_uleb128())
            self.has_children = data.get_uint8()
            fixed_size = 0
            fixed_addrs = 0
            while 1:
                attr = data.get_uleb128()
                form = data.get_uleb128()
                if attr and form:
                    attr_spec = AttributeSpec(attr, form)
                    self.attribute_specs.append(attr_spec)
                    if fixed_size >= 0:
                        attr_fixed_size = attr_spec.form.get_fixed_size()
                        if attr_fixed_size >= 0:
                            fixed_size += attr_fixed_size
                        elif attr_spec.form.is_address():
                            fixed_addrs += 1
                        else:
                            fixed_size = -1
                else:
                    break
            if fixed_size >= 0:
                self.fixed_size = fixed_size
                self.fixed_addrs = fixed_addrs
            return self.tag != 0
        else:
            self.tag = Tag(0)
            self.has_children = False
            self.attribute_specs = list()
            return False

    def get_fixed_size(self, die):
        if self.fixed_size >= 0:
            return (self.fixed_size +
                    self.fixed_addrs * die.cu.dwarf_info.addr_size)
        else:
            return -1

    def skip(self, die, data):
        fixed_size = self.get_fixed_size(die)
        if fixed_size >= 0:
            data.seek(data.tell() + fixed_size)
            return True
        else:
            for attr_spec in self.attribute_specs:
                if not attr_spec.form.skip(die, data):
                    return False
            return True

    def is_null(self):
        return self.tag.is_null()

    def dump(self, f=sys.stdout):
        pass

    def __str__(self):
        if self.has_children:
            child_str = get_color_DW_constant('DW_CHILDREN_yes')
        else:
            child_str = get_color_DW_constant('DW_CHILDREN_no')
        s = '[%u]: %-*s    %s\n' % (self.code, Tag.max_width(),
                                    get_color_tag(self.tag), child_str)

        for attr_spec in self.attribute_specs:
            s += '    ' + str(attr_spec) + '\n'
        return s


class AbbrevSet:
    def __init__(self):
        self.offset = 0
        self.abbrevs = list()

    def encode(self, encoder):
        for abbrev in self.abbrevs:
            abbrev.encode(encoder)
        encoder.put_uint8(0)

    def unpack(self, data):
        self.offset = data.tell()
        abbrev = AbbrevDecl()
        while abbrev.unpack(data):
            self.abbrevs.append(abbrev)
            abbrev = AbbrevDecl()
        return len(self.abbrevs) > 0

    def __str__(self):
        s = '%s:\n' % (get_color_offset(self.offset))
        for abbrev in self.abbrevs:
            s += str(abbrev) + '\n'
        return s

    def getCode(self, abbrev):
        '''Look through all abbreviations and calculate the abbreviation code
        by finding one that matches, or by adding a new one'''
        abbrev_len = len(abbrev.attribute_specs)
        for (idx, curr_abbrev) in enumerate(self.abbrevs):
            if abbrev.tag == curr_abbrev.tag:
                if abbrev.has_children == curr_abbrev.has_children:
                    curr_abbrev_len = len(curr_abbrev.attribute_specs)
                    if abbrev_len == curr_abbrev_len:
                        match = True
                        for i in range(abbrev_len):
                            if (abbrev.attribute_specs[i] !=
                                    curr_abbrev.attribute_specs[i]):
                                match = False
                                break
                        if match:
                            return curr_abbrev.code
        abbrev.code = len(self.abbrevs) + 1
        self.abbrevs.append(abbrev)
        return abbrev.code

    def get_abbrev_decl(self, code):
        if code <= 0:
            return None
        code_idx = code - 1
        if code_idx < len(self.abbrevs):
            if self.abbrevs[code_idx].code == code:
                return self.abbrevs[code_idx]
        for abbrev in self.abbrevs:
            if abbrev.code == code:
                return abbrev
        return None


class DebugAbbrev:
    def __init__(self):
        self.sets = list()

    def unpack(self, data):
        while 1:
            abbrev_set = AbbrevSet()
            if not abbrev_set.unpack(data):
                return
            self.sets.append(abbrev_set)

    def get_abbrev_set(self, debug_abbrev_offset):
        for abbrev_set in self.sets:
            if abbrev_set.offset == debug_abbrev_offset:
                return abbrev_set
        return None

    def __str__(self):
        s = '.debug_abbrev:\n\n'
        for abbrev_set in self.sets:
            s += str(abbrev_set)
        return s


class DebugAranges:
    class Set:
        def __init__(self, dwarf_info=None):
            self.offset = 0
            self.length = 0
            if dwarf_info is None:
                self.dwarf_info = DWARFInfo(addr_size=0, version=0,
                                            dwarf_size=4)
            else:
                self.dwarf_info = dwarf_info
            self.cu_offset = 0
            self.seg_size = 0
            self.address_ranges = None

        def is_valid(self):
            return (self.length > 0 and self.dwarf_info.version <= 5 and
                    self.dwarf_info.addr_size > 0 and
                    len(self.address_ranges) > 0)

        def get_cu_offset_for_address(self, address):
            if self.address_ranges.contains(address):
                return self.cu_offset
            return -1

        def __lt__(self, other):
            '''Provide less than comparison for bisect functions'''
            if type(other) is int:
                return self.address_ranges.max_range.lo < other
            else:
                return (self.address_ranges.max_range.lo <
                        other.address_ranges.max_range.lo)

        def dump(self, f=sys.stdout):
            f.write('%s: length = 0x%8.8x, version = %u, cu_offset = 0x%8.8x, '
                    'addr_size = %u, seg_size = %u' % (
                        get_color_offset(self.offset), self.length,
                        self.dwarf_info.version, self.cu_offset,
                        self.dwarf_info.addr_size, self.seg_size))
            self.address_ranges.dump(f=f, addr_size=self.dwarf_info.addr_size)

        def __str__(self):
            output = StringIO.StringIO()
            self.dump(f=output)
            return output.getvalue()

        def append_range(self, low_pc, high_pc):
            if self.address_ranges is None:
                self.address_ranges = AddressRangeList()
            self.address_ranges.append(AddressRange(low_pc, high_pc))

        def finalize(self):
            if self.address_ranges is not None:
                self.address_ranges.finalize(False)

        def encode(self, encoder):
            self.offset = encoder.file.tell()
            encoder.put_uint32(0)  # unit_length, fixup later
            encoder.put_uint16(self.dwarf_info.version)
            encoder.put_uint_size(self.dwarf_info.dwarf_size, self.cu_offset)
            encoder.put_uint8(self.dwarf_info.addr_size)
            encoder.put_uint8(self.seg_size)
            # Align the first tuple in the right boundary
            encoder.align_to(self.dwarf_info.addr_size*2)
            for address_range in self.address_ranges:
                encoder.put_address(address_range.lo)
                encoder.put_address(address_range.hi - address_range.lo)
            encoder.put_address(0)
            encoder.put_address(0)
            # Fixup the zero unit_length we wrote out earlier
            end_offset = encoder.file.tell()
            unit_length = end_offset - (self.offset + 4)
            encoder.fixup_uint_size(4, unit_length, self.offset)

        def unpack(self, data):
            self.offset = data.tell()
            self.length = data.get_uint32()
            self.dwarf_info.version = data.get_uint16()
            self.cu_offset = data.get_uint32()
            self.dwarf_info.addr_size = data.get_uint8()
            self.seg_size = data.get_uint8()
            if (self.length == 0 or self.dwarf_info.version == 0 or
                    self.dwarf_info.addr_size == 0):
                return False
            data.set_addr_size(self.dwarf_info.addr_size)
            self.address_ranges = AddressRangeList()

            data.align_to(self.dwarf_info.addr_size * 2)

            while 1:
                addr = data.get_address()
                size = data.get_address()
                if addr == 0 and size == 0:
                    break
                self.append_range(addr, addr + size)
            self.finalize()
            return self.is_valid()

    def __init__(self):
        self.sets = None
        self.max_range = None

    def unpack(self, data):
        arange_sets = list()
        arange_set = DebugAranges.Set()
        while arange_set.unpack(data):
            arange_sets.append(arange_set)
            arange_set = DebugAranges.Set()
        self.arange_sets = sorted(arange_sets)
        if len(self.arange_sets):
            self.max_range = AddressRange(
                self.arange_sets[0].address_ranges.max_range.lo,
                self.arange_sets[-1].address_ranges.max_range.hi)

    def get_cu_offset_for_address(self, address):
        if self.max_range and self.max_range.contains(address):
            i = bisect.bisect_left(self.arange_sets, address)
            num = len(self.arange_sets)
            if i == num and num > 0:
                i = num-1
            if i < num:
                if i > 0:
                    off = self.arange_sets[i-1].get_cu_offset_for_address(
                        address)
                    if off >= 0:
                        return off
                return self.arange_sets[i].get_cu_offset_for_address(address)
        return -1

    def dump(self, f=sys.stdout):
        f.write(".debug_aranges:\n\n")
        for arange_set in self.arange_sets:
            arange_set.dump(f=f)

    def __str__(self):
        output = StringIO.StringIO()
        self.dump(f=output)
        return output.getvalue()


class AddressRange:
    def __init__(self, lo, hi):
        self.lo = lo
        self.hi = hi

    def dump(self, f=sys.stdout, addr_size=8):
        if self.lo < self.hi:
            if addr_size == 8:
                f.write('[%#16.16x - %#16.16x)' % (self.lo, self.hi))
            elif addr_size == 4:
                f.write('[%#8.8x - %#8.8x)' % (self.lo, self.hi))
            else:
                f.write('[%#x - 0x%x)' % (self.lo, self.hi))
        else:
            if addr_size == 8:
                f.write('[%#16.16x                     )' % (self.lo))
            elif addr_size == 4:
                f.write('[%#8.8x             )' % (self.lo))
            else:
                f.write('[%#x )' % (self.lo, self.hi))

    def __str__(self):
        if self.lo < self.hi:
            return '[0x%16.16x - 0x%16.16x)' % (self.lo, self.hi)
        else:
            return '[0x%16.16x                     )' % (self.lo)

    def __eq__(self, other):
        return self.lo == other.lo and self.hi == other.hi

    def __ne__(self, other):
        return self.lo != other.lo or self.hi != other.hi

    def __lt__(self, other):
        if type(other) is int:
            return self.lo < other
        else:
            if self.lo < other.lo:
                return True
            else:
                return self.hi < other.hi

    def __le__(self, other):
        if self.lo <= other.lo:
            return True
        else:
            return self.hi <= other.hi

    def __ge__(self, other):
        if self.lo >= other.lo:
            return True
        else:
            return self.hi >= other.hi

    def contains(self, value):
        return self.lo <= value and value < self.hi

    def size(self):
        return self.hi - self.lo


class AddressRangeList:
    def __init__(self):
        self.ranges = list()
        self.max_range = None

    def __len__(self):
        return len(self.ranges)

    def __iter__(self):
        return iter(self.ranges)

    def contains(self, address):
        return not self.get_range_for_address(address) is None

    def get_min_address(self):
        if self.max_range is None:
            return -1
        else:
            return self.max_range.lo

    def encode(self, encoder):
        offset = encoder.file.tell()
        for range in self.ranges:
            encoder.put_address(range.lo)
            encoder.put_address(range.hi)
        encoder.put_address(0)
        encoder.put_address(0)
        return offset

    def get_range_for_address(self, address):
        if self.max_range and self.max_range.contains(address):
            i = bisect.bisect_left(self.ranges, address)
            num = len(self.ranges)
            if i == num and num > 0:
                i = num-1
            if i < num:
                if i > 0 and self.ranges[i-1].contains(address):
                    return self.ranges[i-1]
                elif self.ranges[i].contains(address):
                    return self.ranges[i]
        return None

    def append(self, value):
        if isinstance(value, AddressRange):
            self.ranges.append(copy.copy(value))
        elif isinstance(value, AddressRangeList):
            for range in value.ranges:
                self.ranges.append(copy.copy(range))
        else:
            raise ValueError

    def finalize(self, compress=True):
        num_ranges = len(self.ranges)
        if num_ranges > 1:
            sorted_ranges = sorted(self.ranges)
            if compress:
                compressed_ranges = list()
                for range in sorted_ranges:
                    if (len(compressed_ranges) > 0 and
                            compressed_ranges[-1].hi == range.lo):
                        compressed_ranges[-1].hi = range.hi
                    else:
                        compressed_ranges.append(range)
                self.ranges = compressed_ranges
            else:
                self.ranges = sorted_ranges
        if len(self.ranges):
            self.max_range = AddressRange(self.ranges[0].lo,
                                          self.ranges[-1].hi)

    def dump(self, f=sys.stdout, addr_size=8):
        for r in self.ranges:
            r.dump(f=f, addr_size=addr_size)

    def __str__(self):
        output = StringIO.StringIO()
        self.dump(f=output)
        return output.getvalue()


class DIERanges:
    class Range(AddressRange):
        def __init__(self, lo, hi, die):
            AddressRange.__init__(self, lo, hi)
            self.die = die

        def __str__(self):
            return '0x%8.8x: [0x%16.16x - 0x%16.16x) %s' % (
                self.die.offset, self.lo, self.hi, self.die.get_display_name())

    def __init__(self):
        self.ranges = list()

    def append_die_ranges(self, die, address_range_list):
        for address_range in address_range_list:
            self.ranges.append(DIERanges.Range(
                address_range.lo, address_range.hi, die))

    def append_die_range(self, die, address_range):
        self.ranges.append(DIERanges.Range(
            address_range.lo, address_range.hi, die))

    def lookup_die_by_address(self, address):
        i = bisect.bisect_left(self.ranges, address)
        num = len(self.ranges)
        if i == num and num > 0:
            i = num-1
        if i < num:
            if i > 0 and self.ranges[i-1].contains(address):
                return self.ranges[i-1].die
            elif self.ranges[i].contains(address):
                return self.ranges[i].die
        return None

    def sort(self):
        self.ranges = sorted(self.ranges)

    def dump(self, indent='', f=sys.stdout):
        for r in self.ranges:
            print >>f, '%s%s' % (indent, r)

    def __str__(self):
        output = StringIO.StringIO()
        self.dump(indent='', f=output)
        return output.getvalue()


class DebugRanges:
    class Ranges:
        def __init__(self, cu, offset, ranges):
            self.offset = offset
            self.cu = cu
            self.ranges = ranges

        def get_min_address(self):
            if self.ranges:
                return self.ranges.get_min_address()
            return -1

        def contains(self, address):
            return not self.lookup_address(address) is None

        def lookup_address(self, address):
            i = bisect.bisect_left(self.ranges, address)
            n = len(self.ranges)
            if i == n and n > 0:
                i = n-1
            if i < n:
                if i > 0 and self.ranges[i-1].contains(address):
                    return self.ranges[i-1]
                elif self.ranges[i].contains(address):
                    return self.ranges[i]
            return None

        def dump(self, indent='', f=sys.stdout, flat=False):
            if flat:
                if self.offset >= 0:
                    f.write('0x%8.8x:' % (self.offset))
                for r in self.ranges:
                    f.write(' [%#x-%#x)' % (r.lo, r.hi))
            else:
                if self.offset >= 0:
                    print >>f, '0x%8.8x' % (self.offset)
                for r in self.ranges:
                    print >>f, '%s%s' % (indent, r)

        def __str__(self):
            output = StringIO.StringIO()
            self.dump(indent='', f=output, flat=True)
            return output.getvalue()

    def __init__(self, dwarf):
        self.dwarf = dwarf
        self.ranges = dict()

    def get_debug_ranges_at_offset(self, cu, offset):
        if offset in self.ranges:
            return self.ranges[offset]
        ranges = AddressRangeList()
        addr_size = cu.dwarf_info.addr_size
        data = self.dwarf.debug_ranges_data
        if data:
            data.set_addr_size(addr_size)
            base_address = cu.get_base_address()
            data.seek(offset)
            while 1:
                begin = data.get_address()
                end = data.get_address()
                if begin == 0 and end == 0:
                    ranges.finalize()
                    r = DebugRanges.Ranges(cu, offset, ranges)
                    self.ranges[offset] = r
                    return r
                if addr_size == 4 and begin == 0xffffffff:
                    base_address = end
                elif addr_size == 8 and begin == 0xffffffffffffffff:
                    base_address = end
                else:
                    ranges.append(AddressRange(begin + base_address,
                                               end + base_address))
        return None


class Range(AddressRange):
    def __init__(self, lo, hi, val1, val2):
        AddressRange.__init__(self, lo, hi)
        self.val1 = val1
        self.val2 = val2

    def __str__(self):
        return '[0x%16.16x - 0x%16.16x) val1 = %u, val2 = %u' % (self.lo,
                                                                 self.hi,
                                                                 self.val1,
                                                                 self.val2)


class LineTable:
    def __init__(self, cu):
        self.cu = cu
        self.offset = cu.get_die().get_attribute_value_as_integer(
            DW_AT_stmt_list)
        self.prologue = None
        self.rows = None
        self.sequence_ranges = None
        self.row_arange = Range(sys.maxint, 0, 0, 0)

    def get_item_dictionary(self):
        rows = self.get_rows()
        if rows:
            return {'#0': '.debug_line[0x%8.8x]' % self.offset,
                    'file': self.cu.get_path(),
                    'children': len(rows) > 0,
                    'tree-item-delegate': self}
        return {}

    def get_child_item_dictionaries(self):
        rows = self.get_rows()
        children = list()
        for row in rows:
            children.append(row.get_item_dictionary(self.prologue))
        return children

    def get_sequence_ranges(self):
        if self.sequence_ranges is None:
            unsorted_sequence_ranges = list()
            rows = self.get_rows()
            sequence_start_idx = 0
            for (i, row) in enumerate(rows):
                if row.end_sequence:
                    if sequence_start_idx >= 0:
                        unsorted_sequence_ranges.append(
                            Range(rows[sequence_start_idx].range.lo,
                                  row.range.lo, sequence_start_idx, i))
                    sequence_start_idx = -1
                elif sequence_start_idx == -1:
                    sequence_start_idx = i
            self.sequence_ranges = sorted(unsorted_sequence_ranges)
        return self.sequence_ranges

    def lookup_sequence_range(self, address):
        sequence_ranges = self.get_sequence_ranges()
        i = bisect.bisect_left(sequence_ranges, address)
        n = len(sequence_ranges)
        if i == n and n > 0:
            i = n-1
        if i < n:
            if i > 0 and sequence_ranges[i-1].contains(address):
                return sequence_ranges[i-1]
            elif sequence_ranges[i].contains(address):
                return sequence_ranges[i]
        return None

    def lookup_row_index_in_sequence(self, sequence, address):
        rows = self.get_rows()
        i = bisect.bisect_left(rows, address, sequence.val1, sequence.val2)
        n = len(rows)
        if i == n and n > 0:
            i = n-1
        if i < len(rows):
            if i > 0 and rows[i-1].contains(address):
                return i-1
            elif rows[i].contains(address):
                return i
        return -1

    def lookup_row_in_sequence_range(self, sequence, address):
        row_idx = self.lookup_row_index_in_sequence(sequence, address)
        if row_idx >= 0:
            return self.get_rows()[row_idx]
        return None

    def get_rows_for_range(self, arange):
        rows = self.get_rows()
        matching_rows = list()
        if self.row_arange.contains(arange.lo):
            sequence = self.lookup_sequence_range(arange.lo)
            if sequence:
                row_idx = self.lookup_row_index_in_sequence(sequence,
                                                            arange.lo)
                if row_idx >= 0:
                    rows = self.get_rows()
                    for i in range(row_idx, sequence.val2+1):
                        matching_rows.append(rows[i])
        return matching_rows

    def lookup_address(self, address):
        self.get_rows()
        if self.row_arange.contains(address):
            sequence = self.lookup_sequence_range(address)
            if sequence:
                return self.lookup_row_in_sequence_range(sequence, address)
        return None

    def get_file(self, file_num):
        prologue = self.get_prologue()
        if prologue and prologue.is_valid():
            return prologue.get_file(file_num)
        return ''

    def get_prologue(self):
        if self.prologue is None:
            data = self.cu.debug_info.dwarf.debug_line_data
            if data:
                self.prologue = LineTable.Prologue(self.cu)
                data.seek(self.offset)
                self.prologue.unpack(data)
        return self.prologue

    def get_rows(self, debug=False):
        if self.rows is None:
            prologue = self.get_prologue()
            if prologue is None:
                return None
            self.rows = list()
            if not prologue.is_valid():
                return self.rows
            data = self.cu.debug_info.dwarf.debug_line_data
            offset = prologue.get_rows_offset()
            if offset > 0:
                end_offset = prologue.get_rows_end_offset()
                data.seek(offset)
                row = LineTable.Row(prologue)
                data.set_addr_size(self.cu.dwarf_info.addr_size)
                while data.tell() < end_offset:
                    opcode = data.get_uint8()
                    if debug:
                        print DW_LNS(opcode),
                    if opcode == 0:
                        # Extended opcodes always start with zero followed
                        # by uleb128 length to they can be skipped
                        length = data.get_uleb128()
                        dw_lne = data.get_uint8()
                        if debug:
                            print DW_LNE(dw_lne),
                        if dw_lne == DW_LNE_end_sequence:
                            row.end_sequence = True
                            self.rows.append(copy.copy(row))
                            # Keep up with the max range for the rows
                            if self.row_arange.hi < row.range.lo:
                                self.row_arange.hi = row.range.lo
                            if debug:
                                print ''
                                row.dump(prologue)
                            row = LineTable.Row(prologue)
                        elif dw_lne == DW_LNE_set_address:
                            row.range.lo = data.get_address()
                            if debug:
                                print '(0x%16.16x)' % (row.range.lo),
                        elif dw_lne == DW_LNE_define_file:
                            file_entry = LineTable.File()
                            file_entry.unpack(data)
                            if debug:
                                file_entry.dump(len(prologue.files))
                            prologue.files.append(file_entry)
                        elif dw_lne == DW_LNE_set_discriminator:
                            # We don't use the discriminator, so just
                            # parse it and toss it
                            discriminator = data.get_uleb128()
                            if debug:
                                print '(0x%x)' % (discriminator),
                        else:
                            # Skip unknown extended opcode
                            data.seek(data.tell() + length)
                    elif opcode < prologue.opcode_base:
                        if opcode == DW_LNS_copy:
                            self.rows.append(copy.copy(row))
                            if row.range.lo < self.row_arange.lo:
                                self.row_arange.lo = row.range.lo
                            if debug:
                                print ''
                                row.dump(prologue)
                            row.post_append()
                        elif opcode == DW_LNS_advance_pc:
                            pc_offset = data.get_uleb128()
                            if debug:
                                print '(%u)' % (pc_offset),
                            row.range.lo += pc_offset
                        elif opcode == DW_LNS_advance_line:
                            line_offset = data.get_sleb128()
                            if debug:
                                print '(%i)' % (line_offset),
                            row.line += line_offset
                        elif opcode == DW_LNS_set_file:
                            row.file = data.get_uleb128()
                            if debug:
                                print '(%u)' % (row.file),
                        elif opcode == DW_LNS_set_column:
                            row.column = data.get_uleb128()
                            if debug:
                                print '(%u)' % (row.column),
                        elif opcode == DW_LNS_negate_stmt:
                            row.is_stmt = not row.is_stmt
                        elif opcode == DW_LNS_set_basic_block:
                            row.basic_block = True
                        elif opcode == DW_LNS_const_add_pc:
                            adjust_opcode = 255 - prologue.opcode_base
                            addr_units = adjust_opcode / prologue.line_range
                            addr_offset = addr_units * prologue.min_inst_length
                            if debug:
                                print '(%u)' % (addr_offset),
                            row.range.lo += addr_offset
                        elif opcode == DW_LNS_fixed_advance_pc:
                            pc_offset = data.get_uint16()
                            if debug:
                                print '(%u)' % (pc_offset),
                            row.range.lo += pc_offset
                        elif opcode == DW_LNS_set_prologue_end:
                            row.prologue_end = True
                        elif opcode == DW_LNS_set_epilogue_begin:
                            row.epilogue_begin = True
                        elif opcode == DW_LNS_set_isa:
                            row.isa = data.get_uleb128()
                            if debug:
                                print '(%u)' % (row.isa),
                        else:
                            print 'error: unhandled DW_LNS value %u' % (
                                opcode)
                    else:
                        adjust_opcode = opcode - prologue.opcode_base
                        addr_units = adjust_opcode / prologue.line_range
                        line_units = adjust_opcode % prologue.line_range
                        addr_offset = addr_units * prologue.min_inst_length
                        line_offset = prologue.line_base + line_units
                        if debug:
                            print "0x%2.2x address += %u, line += %d" % (
                                opcode, addr_offset, line_offset),
                        row.line += line_offset
                        row.range.lo += addr_offset
                        self.rows.append(copy.copy(row))
                        if row.range.lo < self.row_arange.lo:
                            self.row_arange.lo = row.range.lo
                        if debug:
                            print ''
                            row.dump(prologue)
                        row.post_append()
                    if debug:
                        print ''
            # Now calculate the end addresses for all rows that aren't
            # end_sequence rows
            prev_row = None
            for row in self.rows:
                if prev_row:
                    prev_row.range.hi = row.range.lo
                if row.end_sequence:
                    row.range.hi = row.range.lo
                    prev_row = None
                else:
                    prev_row = row
        return self.rows

    def dump(self, verbose=False, f=sys.stdout):
        prologue = self.get_prologue()
        if prologue is None:
            return
        colorizer = term_colors.TerminalColors(enable_colors)
        if verbose:
            prologue.dump(verbose=verbose, f=f)
        line_entries = self.get_rows()
        if line_entries:
            f.write('Address                                   Line   File\n')
            f.write('----------------------------------------- ------ '
                    '------------------------------\n')
            last_file = -1
            func_die = None
            for row in line_entries:
                if row.range.lo < row.range.hi:
                    if not (func_die and
                            func_die.get_die_ranges().contains(row.range.lo)):
                        func_die = self.cu.lookup_die_by_address(row.range.lo)
                        if func_die:
                            if verbose:
                                print func_die
                            else:
                                f.write('%s0x%8.8x%s: %s%s%s:\n' % (
                                    colorizer.yellow(), func_die.offset,
                                    colorizer.reset(), colorizer.green(),
                                    func_die.get_display_name(),
                                    colorizer.reset()))
                        else:
                            print >>f, '<???>:'
                if verbose:
                    print row
                else:
                    curr_file = row.file
                    # Skip the last entries that don't have a valid range
                    # (the end_sequence)
                    if row.range.size() > 0:
                        if curr_file != last_file:
                            last_file = curr_file
                            f.write('%s %6u %s\n' % (
                                    row.range, row.line,
                                    prologue.get_file(row.file)))
                        else:
                            print >>f, '%s %6u' % (row.range, row.line)
                if row.end_sequence:
                    print >>f, ''

    def __str__(self):
        output = StringIO.StringIO()
        self.dump(True, output)
        return output.getvalue()

    class Row:
        def __init__(self, prologue):
            self.range = AddressRange(0, 0)
            self.file = 1
            self.line = 1
            self.column = 0
            self.is_stmt = prologue.default_is_stmt
            self.basic_block = False
            self.end_sequence = False
            self.prologue_end = False
            self.epilogue_begin = False
            self.isa = 0

        def encode(self, debug_line, prev=None):
            if prev and not prev.end_sequence:
                # If our address changed, advance it in the state machine
                if self.range.lo > prev.range.lo:
                    debug_line.put_uint8(DW_LNS_advance_pc)
                    debug_line.put_uleb128(self.range.lo - prev.range.lo)
                elif self.range.lo < prev.range.lo:
                    print 'warning: row has address (%#x)' % (self.range.lo),
                    print 'that is less than previous row (%#x)' % (
                            prev.range.lo)
                    # Pretend we have unsigned 32 or 64 bit overflow
                    positive_delta = prev.range.lo - self.range.lo
                    debug_line.put_uint8(DW_LNS_advance_pc)
                    debug_line.put_uleb128(0xffffffffffffffff -
                                           positive_delta + 1)
                # If our file changed, set it
                if self.file != prev.file:
                    debug_line.put_uint8(DW_LNS_set_file)
                    debug_line.put_uleb128(self.file)
                # If our line number changed, advance it in the state machine
                line_delta = self.line - prev.line
                if line_delta != 0:
                    debug_line.put_uint8(DW_LNS_advance_line)
                    debug_line.put_sleb128(line_delta)
                # If our column changed, set it
                if self.column != prev.column:
                    debug_line.put_uint8(DW_LNS_set_column)
                    debug_line.put_uleb128(self.column)
            else:
                # Extended opcode
                debug_line.put_uint8(0)
                # Extended opcode length including DW_LNE_XXX
                debug_line.put_uleb128(1 + debug_line.addr_size)
                debug_line.put_uint8(DW_LNE_set_address)
                debug_line.put_address(self.range.lo)
                if self.file > 1:
                    debug_line.put_uint8(DW_LNS_set_file)
                    debug_line.put_uleb128(self.file)
                if self.line > 1:
                    debug_line.put_uint8(DW_LNS_advance_line)
                    debug_line.put_sleb128(self.line - 1)
                if self.column > 0:
                    debug_line.put_uint8(DW_LNS_set_column)
                    debug_line.put_uleb128(self.column)
                if self.isa != 0:
                    debug_line.put_uint8(DW_LNS_set_isa)
                    debug_line.put_uleb128(self.isa)
            if self.basic_block:
                debug_line.put_uint8(DW_LNS_set_basic_block)
            if self.prologue_end:
                debug_line.put_uint8(DW_LNS_set_prologue_end)
            if self.epilogue_begin:
                debug_line.put_uint8(DW_LNS_set_epilogue_begin)
            if self.end_sequence:
                # Extended opcode
                debug_line.put_uint8(0)
                # Extended opcode length including DW_LNE_XXX
                debug_line.put_uleb128(1)
                debug_line.put_uint8(DW_LNE_end_sequence)
            else:
                debug_line.put_uint8(DW_LNS_copy)

        def get_item_dictionary(self, prologue):
            return {'#0': '0x%16.16x' % (self.range.lo),
                    'file': prologue.get_file(self.file),
                    'line': str(self.line),
                    'column': str(self.column),
                    'is_stmt': 1 if self.is_stmt else 0,
                    'basic_block': 1 if self.basic_block else 0,
                    'end_sequence': 1 if self.end_sequence else 0,
                    'prologue_end': 1 if self.prologue_end else 0,
                    'epilogue_begin': 1 if self.epilogue_begin else 0,
                    'isa': self.isa,
                    'children': False}

        def __lt__(self, other):
            if type(other) is int:
                return self.range.lo < other
            return self.range < other.range

        def contains(self, addr):
            return self.range.contains(addr)

        def post_append(self):
            # Called after a row is appended to the matrix
            self.basic_block = False
            self.prologue_end = False
            self.epilogue_begin = False
            self.range = AddressRange(self.range.lo, self.range.hi)

        def dump_lookup_results(self, prologue, f=sys.stdout):
            cu = prologue.cu
            cu_die = cu.get_die()
            print >>f, '.debug_info[0x%8.8x]: %s' % (cu_die.get_offset(),
                                                     cu.get_path())
            filepath = prologue.get_file(self.file)
            print >>f, '.debug_line[0x%8.8x]: %s %s:%u' % (prologue.offset,
                                                           self.range,
                                                           filepath,
                                                           self.line)

        def dump(self, prologue, f=sys.stdout):
            print >>f, '0x%16.16x %5u %5u %5u' % (self.range.lo,
                                                  self.file,
                                                  self.line,
                                                  self.column),
            if self.is_stmt:
                print >>f, 'is_stmt',
            if self.basic_block:
                print >>f, 'basic_block',
            if self.end_sequence:
                print >>f, 'end_sequence',
            if self.prologue_end:
                print >>f, 'prologue_end',
            if self.epilogue_begin:
                print >>f, 'epilogue_begin',
            if self.isa:
                print >>f, 'isa = %u' % (self.isa),

        def __str__(self):
            output = StringIO.StringIO()
            self.dump(True, output)
            return output.getvalue()

    class File:
        def __init__(self):
            self.name = None
            self.dir_idx = None
            self.mod_time = None
            self.length = None
            # Fixed up path
            self.path = None

        def encode(self, debug_line):
            debug_line.put_c_string(self.name)
            debug_line.put_uleb128(self.dir_idx)
            debug_line.put_uleb128(self.mod_time)
            debug_line.put_uleb128(self.length)

        def get_path(self, prologue):
            if self.path is None:
                if self.name.startswith('/'):
                    self.path = self.name
                elif self.dir_idx == 0:
                    cu_die = prologue.cu.get_die()
                    comp_dir = cu_die.get_attribute_value_as_string(
                        DW_AT_comp_dir)
                    if comp_dir:
                        self.path = os.path.join(comp_dir, self.name)
                    else:
                        self.path = self.name
                else:
                    directory = prologue.directories[self.dir_idx-1]
                    path = os.path.join(directory, self.name)
                    if not path.startswith('/'):
                        cu_die = prologue.cu.get_die()
                        comp_dir = cu_die.get_attribute_value_as_string(
                            DW_AT_comp_dir)
                        if comp_dir:
                            path = os.path.join(comp_dir, path)
                    self.path = path
                self.path = os.path.normpath(self.path)
            return self.path

        def dump(self, i, f=sys.stdout):
            f.write('prologue.file[%u] = { name = "%s", dir_idx = %u, '
                    'mod_time = 0x%x, length = 0x%x }\n' % (
                        i, self.name, self.dir_idx, self.mod_time,
                        self.length))

        def unpack(self, data):
            self.name = data.get_c_string()
            if not self.name:
                return False
            self.dir_idx = data.get_uleb128()
            self.mod_time = data.get_uleb128()
            self.length = data.get_uleb128()
            return True

    class Prologue:
        def __init__(self, cu):
            self.cu = cu
            self.offset = 0
            self.total_length = 0
            self.version = 0
            self.prologue_length = 0
            self.min_inst_length = 0
            self.default_is_stmt = 0
            self.line_base = 0
            self.line_range = 0
            self.opcode_base = 0
            self.opcode_lengths = None
            self.directories = None
            self.files = None
            self.rows_offset = 0

        def generate_init(self):
            '''Initialize this class for use with the DWARF generator'''
            self.version = 2
            self.min_inst_length = 1
            self.default_is_stmt = 1
            self.line_base = -5
            self.line_range = 14
            self.opcode_base = 0xd
            self.opcode_lengths = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]
            self.directories = list()
            self.files = list()

        def add_directory(self, dir):
            '''Function used with DWARF generation to add a directory to the
               line table prologue'''
            if dir not in self.directories:
                self.directories.append(dir)
            return self.directories.index(dir) + 1

        def add_file(self, fullpath):
            '''Function used with DWARF generation to add a file to the
               line table prologue'''
            (dir, basename) = os.path.split(fullpath)
            dir_idx = self.add_directory(dir)
            for (i, file) in enumerate(self.files):
                if file.dir_idx == dir_idx and file.name == basename:
                    return i+1
            file = LineTable.File()
            file.name = basename
            file.dir_idx = dir_idx
            file.mod_time = 0
            file.length = 0
            self.files.append(file)
            return len(self.files)

        def is_valid(self):
            return (self.total_length > 0 and self.version <= 5 and
                    self.prologue_length > 0 and len(self.opcode_lengths) > 0
                    and len(self.files) > 0)

        def dump(self, verbose, f=sys.stdout):
            print >>f, '.debug_line[0x%8.8x]:' % (self.offset)
            if verbose:
                print >>f, 'prologue.total_length    = 0x%8.8x' % (
                        self.total_length)
                print >>f, 'prologue.version         = 0x%4.4x' % (
                        self.version)
                print >>f, 'prologue.prologue_length = 0x%8.8x' % (
                        self.prologue_length)
                print >>f, 'prologue.min_inst_length = %i' % (
                        self.min_inst_length)
                print >>f, 'prologue.default_is_stmt = %i' % (
                        self.default_is_stmt)
                print >>f, 'prologue.line_base       = %i' % (
                        self.line_base)
                print >>f, 'prologue.line_range      = %u' % (
                        self.line_range)
                print >>f, 'prologue.opcode_base     = %u' % (
                        self.opcode_base)
                max_len = DW_LNS.max_width()
                for (i, op_len) in enumerate(self.opcode_lengths):
                    dw_lns = DW_LNS(i+1)
                    print >>f, 'prologue.opcode_lengths[%-*s] = %u' % (max_len,
                                                                       dw_lns,
                                                                       op_len)
                for (i, directory) in enumerate(self.directories):
                    print >>f, 'prologue.directories[%u] = "%s"' % (i+1,
                                                                    directory)
                for (i, filename) in enumerate(self.files):
                    filename.dump(i+1, f=f)
            else:
                for (i, directory) in enumerate(self.directories):
                    print >>f, 'directory[%u] = "%s"' % (i+1, directory)
                for (i, filename) in enumerate(self.files):
                    print >>f, 'file[%u] = "%s"' % (i+1,
                                                    filename.get_path(self))

        def get_file(self, file_num):
            file_idx = file_num - 1
            if file_idx >= 0 and file_idx < len(self.files):
                return self.files[file_idx].get_path(self)
            return None

        def get_file_paths(self):
            files = list()
            if self.files is not None:
                for f in self.files:
                    files.append(f.get_path(self))
            return files

        def get_rows_offset(self):
            return self.rows_offset

        def get_rows_end_offset(self):
            return self.offset + self.total_length + 4

        def __str__(self):
            output = StringIO.StringIO()
            self.dump(True, output)
            return output.getvalue()

        def encode(self, debug_line):
            self.offset = debug_line.tell()
            # We will need to fixup total_length later
            debug_line.put_uint32(0)
            debug_line.put_uint16(self.version)
            prologue_length_off = debug_line.tell()
            # We will need to fixup prologue_length later
            debug_line.put_uint32(0)
            debug_line.put_uint8(self.min_inst_length)
            debug_line.put_uint8(self.default_is_stmt)
            debug_line.put_sint8(self.line_base)
            debug_line.put_uint8(self.line_range)
            debug_line.put_uint8(self.opcode_base)
            for opcode_length in self.opcode_lengths:
                debug_line.put_uint8(opcode_length)
            for directory in self.directories:
                debug_line.put_c_string(directory)
            # Terminate directories
            debug_line.put_uint8(0)
            for file in self.files:
                file.encode(debug_line)
            # Terminate files
            debug_line.put_uint8(0)
            end_header_offset = debug_line.tell()
            # Fix up the
            prologue_length = end_header_offset - (prologue_length_off + 4)
            debug_line.fixup_uint_size(4, prologue_length, prologue_length_off)

        def unpack(self, data):
            self.offset = data.tell()
            self.total_length = data.get_uint32()
            self.version = data.get_uint16()
            self.prologue_length = data.get_uint32()
            end_prologue_offset = self.prologue_length + data.tell()
            self.min_inst_length = data.get_uint8()
            self.default_is_stmt = data.get_uint8() != 0
            self.line_base = data.get_sint8()
            self.line_range = data.get_uint8()
            self.opcode_base = data.get_uint8()
            self.opcode_lengths = list()
            self.directories = list()
            self.files = list()
            self.offset
            for i in range(1, self.opcode_base):
                self.opcode_lengths.append(data.get_uint8())
            s = data.get_c_string()
            while s:
                self.directories.append(s)
                s = data.get_c_string()
            f = LineTable.File()
            while f.unpack(data):
                self.files.append(f)
                f = LineTable.File()
            self.rows_offset = data.tell()
            if self.rows_offset != end_prologue_offset:
                print 'error: error parsing prologue, end offset',
                print '0x%8.8x != actual offset 0x%8.8x' % (
                        end_prologue_offset, self.rows_offset)
                print str(self)
            return self.is_valid()


class DIESearch:
    def __init__(self, tag_match=None):
        self.tag_match = tag_match

    def die_matches(self, die):
        if self.tag_match:
            if not self.tag_match(die.get_tag()):
                return False
        return True


class DIE:
    def __init__(self, cu, cu_die_index, depth):
        self.cu = cu
        self.cu_die_index = cu_die_index
        self.offset = 0
        self.data_offset = 0
        self.abbrev_code = 0
        self.depth = depth
        self.abbrev = None
        self.child = None
        self.name = -1
        self.mangled = -1
        self.demangled = -1
        self.user_visible_name = -1
        self.ranges = None

    def search(self, search, depth=sys.maxsize):
        matching_dies = list()
        if search.die_matches(self):
            matching_dies.append(self)
        if depth > 0:
            child = self.get_child()
            if child:
                sibling = child.get_sibling()
                while sibling:
                    matching_dies.extend(sibling.search(search, depth-1))
                    sibling = sibling.get_sibling()
        return matching_dies

    def unpack(self, data):
        self.offset = data.tell()
        self.abbrev_code = data.get_uleb128()
        self.data_offset = data.tell()
        return self.offset != self.data_offset

    def get_tag(self):
        abbrev_decl = self.get_abbrev_decl()
        if abbrev_decl:
            return abbrev_decl.tag
        else:
            return Tag(0)

    def get_item_dictionary(self):
        abbrev_decl = self.get_abbrev_decl()
        if abbrev_decl:
            tag_name = str(abbrev_decl.tag)
        else:
            tag_name = str(Tag(0))
        name = self.get_name()
        if not name:
            name = ''
        self.get_abbrev_decl()
        return {'#0': '0x%8.8x' % (self.offset),
                'name': tag_name,
                'value': name,
                'children': abbrev_decl and abbrev_decl.has_attributes(),
                'tree-item-delegate': self}

    def get_child_item_dictionaries(self):
        item_dicts = list()
        child_dies = self.get_children()
        attr_values = self.get_attribute_values()
        for attr_value in attr_values:
            item_dicts.append(attr_value.get_item_dictionary(self))
        for die in child_dies:
            item_dicts.append(die.get_item_dictionary())
        return item_dicts

    def __lt__(self, offset):
        return self.offset < offset

    def is_valid(self):
        return self.offset != 0

    def lookup_address(self, address):
        '''Find the deepest most child DIE that still contains address'''
        die_ranges = self.get_die_ranges()
        if die_ranges.contains(address):
            for die in self.get_children():
                lookup_die = die.lookup_address(address)
                if lookup_die:
                    return lookup_die
            return self
        else:
            return None

    def get_name(self):
        if self.name is -1:
            self.name = self.get_attribute_value_as_string(DW_AT_name)
        return self.name

    def get_debug_ranges(self):
        '''Get the DW_AT_ranges address ranges only. Don't check the
        low_pc or high_pc'''
        ranges_offset = self.get_attribute_value_as_integer(DW_AT_ranges, -1)
        if ranges_offset >= 0:
            debug_ranges = self.cu.debug_info.dwarf.get_debug_ranges()
            if debug_ranges:
                return debug_ranges.get_debug_ranges_at_offset(self.cu,
                                                               ranges_offset)
        return None

    def get_die_ranges(self):
        '''Get the DIE's address range using DW_AT_ranges, or the
        low_pc/high_pc, or global variable'''
        if self.ranges is None:
            debug_ranges = self.get_debug_ranges()
            if debug_ranges:
                self.ranges = debug_ranges.ranges
            else:
                self.ranges = AddressRangeList()
                # No DW_AT_ranges attribute, look for high/low PC
                low_pc = self.get_attribute_value_as_integer(DW_AT_low_pc, -1)
                if low_pc >= 0:
                    high_pc_attr_value = self.get_attribute_value(
                        DW_AT_high_pc)
                    if high_pc_attr_value:
                        if high_pc_attr_value.attr_spec.form.is_address():
                            high_pc = high_pc_attr_value.value
                        else:
                            high_pc = low_pc + high_pc_attr_value.value
                        if low_pc < high_pc:
                            self.ranges.append(AddressRange(low_pc, high_pc))
                else:
                    global_addr = self.get_global_variable_address()
                    if global_addr >= 0:
                        byte_size = self.get_byte_size()
                        if byte_size > 0:
                            self.ranges.append(
                                AddressRange(global_addr,
                                             global_addr + byte_size))
                self.ranges.finalize()
        return self.ranges

    def get_global_variable_address(self):
        abbrev_decl = self.get_abbrev_decl()
        if abbrev_decl:
            tag = abbrev_decl.tag.get_enum_value()
            if tag == DW_TAG_variable:
                location_attr_value = self.get_attribute_value(DW_AT_location)
                if location_attr_value:
                    location = location_attr_value.get_value(self)
                    if location.has_file_address():
                        value = location.evaluate()
                        if value:
                            return value.value
        return -1

    def get_array_bounds(self):
        abbrev_decl = self.get_abbrev_decl()
        if abbrev_decl:
            tag = abbrev_decl.tag.get_enum_value()
            if tag == DW_TAG_array_type:
                return self.get_child().get_array_bounds()
            elif tag == DW_TAG_subrange_type:
                bound = None
                attr_values = self.get_attribute_values(False)
                if attr_values:
                    lo = 0
                    hi = -1
                    for attr_value in attr_values:
                        attr = attr_value.attr_spec
                        attr_enum_value = attr.attr.get_enum_value()
                        if attr_enum_value == DW_AT_count:
                            lo = 0
                            hi = attr_value.value
                        elif attr_enum_value == DW_AT_lower_bound:
                            lo = attr_value.value
                        elif attr_enum_value == DW_AT_upper_bound:
                            hi = attr_value.value + 1
                    if lo <= hi:
                        bound = (lo, hi)
                child = self.get_child()
                if bound:
                    bounds = [bound]
                    if child:
                        child_bound = self.get_array_bounds()
                        if child_bound:
                            bounds.extend(child_bound)
                    return bounds
        return None

    def get_byte_size(self):
        abbrev_decl = self.get_abbrev_decl()
        if abbrev_decl:
            byte_size = self.get_attribute_value_as_integer(DW_AT_byte_size,
                                                            -1)
            if byte_size >= 0:
                return byte_size
            tag = abbrev_decl.tag.get_enum_value()
            if tag in [DW_TAG_pointer_type,
                       DW_TAG_reference_type,
                       DW_TAG_ptr_to_member_type]:
                return self.cu.dwarf_info.addr_size
            elif tag == DW_TAG_array_type:
                type_die_offset = self.get_attribute_value_as_integer(
                    DW_AT_type, -1)
                if type_die_offset >= 0:
                    type_die = self.get_referenced_die_with_offset(
                        type_die_offset)
                    if type_die:
                        type_byte_size = type_die.get_byte_size()
                        if type_byte_size >= 0:
                            bounds = self.get_array_bounds()
                            if bounds:
                                array_byte_size = 0
                                for (lo, hi) in bounds:
                                    array_byte_size += type_byte_size * (hi - lo)
                                return array_byte_size
            else:
                type_die = self.get_attribute_value_as_die(DW_AT_type)
                if type_die:
                    type_byte_size = type_die.get_byte_size()
                    if type_byte_size >= 0:
                        return type_byte_size
        return -1

    def append_die_ranges(self, die_ranges):
        arange_list = self.get_die_ranges()
        if arange_list:
            die_ranges.append_die_ranges(self, arange_list)

    def get_mangled_name(self):
        if self.mangled is -1:
            self.mangled = self.get_first_attribute_value_as_string(
                [DW_AT_MIPS_linkage_name, DW_AT_linkage_name])
        return self.mangled

    def get_demangled_name(self):
        if self.demangled is -1:
            mangled = self.get_mangled_name()
            if mangled:
                self.demangled = commands.getoutput('c++filt -n %s' % (
                    mangled))
            else:
                self.demangled = None
        return self.demangled

    def get_decl_context_as_string(self):
        parent = self.get_parent()
        if parent:
            tag = parent.get_tag().get_enum_value()
            if tag in [DW_TAG_class_type,
                       DW_TAG_structure_type,
                       DW_TAG_union_type, DW_TAG_namespace,
                       DW_TAG_subprogram,
                       DW_TAG_lexical_block,
                       DW_TAG_inlined_subroutine]:
                parent_mangled = parent.get_mangled_name()
                if parent_mangled:
                    return parent.get_display_name()
                else:
                    parent_decl_ctx = parent.get_decl_context_as_string()
                    parent_name = parent.get_name()
                    if parent_decl_ctx:
                        if parent_name:
                            return parent_decl_ctx + '::' + parent_name
                        else:
                            return parent_decl_ctx
                    else:
                        return parent.get_name()
        return None

    def get_display_name(self):
        if self.user_visible_name is -1:
            self.user_visible_name = None
            demangled = self.get_demangled_name()
            if demangled:
                self.user_visible_name = demangled
            else:
                name = self.get_name()
                if name:
                    decl_ctx = self.get_decl_context_as_string()
                    if decl_ctx:
                        self.user_visible_name = decl_ctx + '::' + name
                    else:
                        self.user_visible_name = name
        return self.user_visible_name

    def get_offset(self):
        return self.offset

    def get_abbrev_decl(self):
        if self.abbrev is None:
            abbrev_set = self.cu.get_abbrev_set()
            if abbrev_set:
                self.abbrev = abbrev_set.get_abbrev_decl(self.abbrev_code)
            else:
                print("error: compile unit at 0x%8.8x can't find its abbrev "
                      "set..." % (self.cu.offset))
                exit(1)
        return self.abbrev

    def get_first_attribute_value(self, attr_enum_values):
        abbrev_decl = self.get_abbrev_decl()
        if abbrev_decl and abbrev_decl.might_have_any_attributes(
                attr_enum_values):
            data = self.cu.data
            data.seek(self.data_offset)
            other_die_offsets = list()
            for attr_spec in abbrev_decl.attribute_specs:
                curr_attr_enum_value = attr_spec.attr.get_enum_value()
                if curr_attr_enum_value in attr_enum_values:
                    attr_value = AttributeValue(attr_spec)
                    debug_str = self.cu.debug_info.dwarf.debug_str_data
                    if attr_value.extract_value(self, data, debug_str):
                        return attr_value
                elif (curr_attr_enum_value == DW_AT_abstract_origin or
                      curr_attr_enum_value == DW_AT_specification):
                    attr_value = AttributeValue(attr_spec)
                    debug_str = self.cu.debug_info.dwarf.debug_str_data
                    if attr_value.extract_value(self, data, debug_str):
                        other_die_offsets.append(attr_value.value)
                else:
                    if not attr_spec.form.skip(self, data):
                        print('error: failed to skip the attribute %s in die '
                              '0x%8.8x' % (attr_spec, self.offset))
                        return None
            for die_offset in other_die_offsets:
                die = self.get_referenced_die_with_offset(die_offset)
                if die:
                    attr_value = die.get_first_attribute_value(
                        attr_enum_values)
                    if attr_value:
                        return attr_value
        return None

    def get_first_attribute_value_as_string(self, attr_enum_values):
        attr_value = self.get_first_attribute_value(attr_enum_values)
        if attr_value and is_string(attr_value.value):
            return attr_value.value
        return None

    def get_attribute_value(self, attr_enum_value):
        abbrev_decl = self.get_abbrev_decl()
        if abbrev_decl and abbrev_decl.might_have_attribute(attr_enum_value):
            data = self.cu.data
            data.seek(self.data_offset)
            other_die_offsets = list()
            for attr_spec in abbrev_decl.attribute_specs:
                curr_attr_enum_value = attr_spec.attr.get_enum_value()
                if curr_attr_enum_value == attr_enum_value:
                    attr_value = AttributeValue(attr_spec)
                    debug_str = self.cu.debug_info.dwarf.debug_str_data
                    if attr_value.extract_value(self, data, debug_str):
                        return attr_value
                    else:
                        print 'error: failed to extract attribute value...'
                        return None
                elif (curr_attr_enum_value == DW_AT_abstract_origin or
                      curr_attr_enum_value == DW_AT_specification):
                    attr_value = AttributeValue(attr_spec)
                    debug_str = self.cu.debug_info.dwarf.debug_str_data
                    if attr_value.extract_value(self, data, debug_str):
                        other_die_offsets.append(attr_value.value)
                else:
                    if not attr_spec.form.skip(self, data):
                        print('error: failed to skip the attribute %s in die '
                              '0x%8.8x' % (attr_spec, self.offset))
                        return None
            for die_offset in other_die_offsets:
                die = self.get_referenced_die_with_offset(die_offset)
                if die:
                    attr_value = die.get_attribute_value(attr_enum_value)
                    if attr_value:
                        return attr_value
        return None

    def get_attribute_value_as_integer(self, attr_enum_value, fail_value=0):
        attr_value = self.get_attribute_value(attr_enum_value)
        if attr_value:
            if type(attr_value.value) is int:
                return attr_value.value
        return fail_value

    def get_attribute_value_as_string(self, attr_enum_value, fail_value=None):
        attr_value = self.get_attribute_value(attr_enum_value)
        if attr_value:
            if is_string(attr_value.value):
                return attr_value.value
        return fail_value

    def get_attribute_value_as_die(self, attr_enum_value):
        attr_value = self.get_attribute_value(attr_enum_value)
        if attr_value:
            if type(attr_value.value) is int:
                return self.get_referenced_die_with_offset(attr_value.value)
        return None

    def get_attribute_values(self,
                             include_specification_and_abstract_origin=False):
        abbrev_decl = self.get_abbrev_decl()
        if abbrev_decl:
            other_die_offsets = list()
            attr_values = list()
            data = self.cu.data
            debug_str_data = self.cu.debug_info.dwarf.debug_str_data
            data.seek(self.data_offset)
            other_die_offsets = list()
            for attr_spec in abbrev_decl.attribute_specs:
                attr_value = AttributeValue(attr_spec)
                if attr_value.extract_value(self, data, debug_str_data):
                    attr_values.append(attr_value)
                    if include_specification_and_abstract_origin:
                        attr = attr_value.attr_spec.attr
                        attr_enum_value = attr.get_enum_value()
                        if (attr_enum_value == DW_AT_abstract_origin or
                                attr_enum_value == DW_AT_specification):
                            other_die_offsets.append(attr_value.value)
                else:
                    print('error: failed to extract a value for %s in die '
                          '0x%8.8x' % (attr_spec, self.offset))
            for die_offset in other_die_offsets:
                die = self.get_referenced_die_with_offset(die_offset)
                if die:
                    spec_values = die.get_attribute_values(attr_enum_value)
                    if spec_values:
                        attr_values.extend(spec_values)
            return attr_values
        return None

    def get_referenced_die_with_offset(self, die_offset):
        if self.cu.contains_offset(die_offset):
            return self.cu.get_die_with_offset(die_offset)
        else:
            return self.cu.debug_info.find_die_with_offset(die_offset)

    def dump_ancestry(self, verbose=False, show_all_attrs=False, f=sys.stdout):
        parent = self.get_parent()
        if parent:
            parent.dump_ancestry(verbose=verbose,
                                 show_all_attrs=show_all_attrs,
                                 f=f)
        self.dump(max_depth=0,
                  verbose=verbose,
                  show_all_attrs=show_all_attrs,
                  f=f)

    def dump(self, max_depth=0, verbose=False, show_all_attrs=False,
             f=sys.stdout):
        abbrev_decl = self.get_abbrev_decl()
        colorizer = term_colors.TerminalColors(enable_colors)
        if abbrev_decl:
            f.write('%s0x%8.8x%s:  %*s%s%s%s [%u]' % (colorizer.yellow(),
                    self.get_offset(), colorizer.reset(),
                    self.depth * indent_width, '', colorizer.blue(),
                    abbrev_decl.tag, colorizer.reset(), abbrev_decl.code))
            if verbose:
                f.write(colorizer.faint())
                if abbrev_decl.has_children:
                    f.write('DW_CHILDREN_yes')
                else:
                    f.write('DW_CHILDREN_no')
                f.write(colorizer.reset())
                f.write('\n')
            else:
                print >>f, ''

            attr_values = self.get_attribute_values(show_all_attrs)
            for attr_value in attr_values:
                attr_value.dump(die=self, verbose=verbose, f=f)
            f.write('\n')

            if max_depth > 0:
                child = self.get_child()
                if child:
                    child.dump(max_depth=max_depth-1, verbose=verbose, f=f)
                    sibling = child.get_sibling()
                    while sibling:
                        sibling.dump(max_depth=max_depth-1, verbose=verbose,
                                     f=f)
                        sibling = sibling.get_sibling()
        else:
            f.write('%s0x%8.8x%s:  %*sNULL\n\n' % (colorizer.yellow(),
                    self.get_offset(), colorizer.reset(),
                    self.depth * indent_width, ''))

    def __str__(self):
        output = StringIO.StringIO()
        self.dump(max_depth=0, verbose=False, f=output)
        return output.getvalue()

    def get_children(self):
        children = list()
        die = self.get_child()
        while die:
            children.append(die)
            die = die.get_sibling()
        return children

    def get_child(self):
        abbrev_decl = self.get_abbrev_decl()
        if abbrev_decl and abbrev_decl.has_children:
            return self.cu.dies[self.cu_die_index+1]
        else:
            return None

    def get_sibling(self):
        for i in range(self.cu_die_index+1, len(self.cu.dies)):
            depth = self.cu.dies[i].depth
            if depth > self.depth:
                continue
            if depth == self.depth:
                return self.cu.dies[i]
            if depth < self.depth:
                return None
        return None

    def get_parent(self):
        if self.cu_die_index > 0:
            parent_depth = self.depth - 1
            for i in range(self.cu_die_index-1, -1, -1):
                depth = self.cu.dies[i].depth
                if depth == parent_depth:
                    return self.cu.dies[i]
        return None


class CompileUnit:
    '''DWARF compile unit class'''
    def __init__(self, debug_info):
        self.debug_info = debug_info
        self.data = None
        self.offset = 0
        self.length = 0
        self.dwarf_info = DWARFInfo(addr_size=0, version=0, dwarf_size=4)
        self.abbrev_offset = 0
        self.path = None
        self.dies = None
        self.abbrev_set = None
        self.line_table = None
        self.base_address = -1
        self.aranges = None
        self.die_ranges = None

    def __lt__(self, other):
        if type(other) is int:
            return self.offset < other
        else:
            raise ValueError

    def unpack(self, data):
        self.data = data
        self.offset = data.tell()
        self.length = data.get_uint32()
        self.dwarf_info.version = data.get_uint16()
        self.abbrev_offset = data.get_uint32()
        self.dwarf_info.addr_size = data.get_uint8()
        if self.dwarf_info.addr_size == 4 or self.dwarf_info.addr_size == 8:
            data.set_addr_size(self.dwarf_info.addr_size)
        return self.is_valid()

    def get_base_address(self):
        if self.base_address == -1:
            die = self.get_die()
            if die:
                self.base_address = die.get_attribute_value_as_integer(
                    DW_AT_low_pc, -1)
                if self.base_address == -1:
                    ranges = self.get_ranges()
                    if ranges:
                        self.base_address = ranges.get_min_address()
                    else:
                        self.base_address = 0
        return self.base_address

    def get_ranges(self):
        if self.aranges is None:
            self.aranges = DebugRanges.Ranges(self, self.get_die().offset, [])
            die = self.get_die()
            if die:
                self.aranges = die.get_ranges()
        return self.aranges

    def get_die_ranges(self):
        '''Calculate the address map that maps address ranges to DIE offsets'''
        if self.die_ranges is None:
            self.die_ranges = DIERanges()
            dies = self.get_dies()
            for die in dies:
                tag = die.get_tag()
                if tag == DW_TAG_subprogram or tag == DW_TAG_variable:
                    die.append_die_ranges(self.die_ranges)
            self.die_ranges.sort()
        return self.die_ranges

    def get_path(self):
        if self.path is None:
            self.path = ''
            die = self.get_die()
            if die:
                name = die.get_name()
                self.path = name
                if not name.startswith('/'):
                    comp_dir = die.get_attribute_value_as_string(
                        DW_AT_comp_dir)
                    if comp_dir:
                        self.path = os.path.join(comp_dir, name)
        return self.path

    def get_file(self, file_num):
        line_table = self.get_line_table()
        if line_table:
            return line_table.get_file(file_num)
        return None

    def contains_offset(self, offset):
        return self.offset <= offset and offset < self.get_next_cu_offset()

    def dump(self, verbose, max_depth=sys.maxint, f=sys.stdout):
        print >>f, str(self)
        die = self.get_die()
        die.dump(verbose=verbose, max_depth=max_depth, f=f)

    def is_valid(self):
        return (self.length > 0 and
                self.dwarf_info.version > 0 and
                self.dwarf_info.version <= 7 and
                self.dwarf_info.addr_size > 0)

    def __str__(self):
        return ('%s: Compile Unit: length = 0x%8.8x, version = 0x%4.4x, '
                'abbrev_offset = 0x%8.8x, addr_size = 0x%2.2x (next CU at '
                '0x%8.8x)') % (get_color_offset(self.offset), self.length,
                               self.dwarf_info.version, self.abbrev_offset,
                               self.dwarf_info.addr_size,
                               self.get_next_cu_offset())

    def get_line_table(self):
        if self.line_table is None:
            self.line_table = LineTable(self)
        return self.line_table

    def get_next_cu_offset(self):
        return self.offset + self.length + 4

    def get_header_byte_size(self):
        # Sizes below are: sizeof(unit_length) + sizeof(version) +
        # sizeof(debug_abbrev_offset) + sizeof(address_size)
        if self.dwarf_info.dwarf_size == 8:
            return 12 + 2 + 8 + 1
        else:
            return 4 + 2 + 4 + 1

    def get_first_die_offset(self):
        return self.offset + self.get_header_byte_size()

    def get_die_with_offset(self, die_offset):
        self.get_die()
        i = bisect.bisect_left(self.dies, die_offset)
        if i < len(self.dies) and self.dies[i].offset == die_offset:
            return self.dies[i]
        return None

    def find_dies_with_name(self, name):
        matching_dies = list()
        dies = self.get_dies()
        for die in dies:
            die_name = die.get_name()
            if die_name:
                if die_name == name:
                    matching_dies.append(die)
        if len(matching_dies):
            return matching_dies
        return None

    def get_dies(self):
        if self.dies is None:
            self.dies = list()
            self.get_abbrev_set()
            data = self.data
            data.seek(self.get_first_die_offset())
            end_offset = self.get_next_cu_offset()
            depth = 0
            while data.tell() < end_offset:
                die = DIE(self, len(self.dies), depth)
                die.unpack(data)
                abbrev_decl = die.get_abbrev_decl()
                if die.is_valid():
                    self.dies.append(die)
                else:
                    print 'error: not able to decode die'
                    exit(1)

                if abbrev_decl is None:
                    depth -= 1
                else:
                    if abbrev_decl.has_children:
                        depth += 1
                    if not abbrev_decl.skip(die, data):
                        print('error: failed to skip DIE 0x%8.8x' % (
                              die.get_offset()))
                        exit(2)
                if depth < 0:
                    break
        return self.dies

    def get_die(self):
        '''Get the compile unit DIE'''
        dies = self.get_dies()
        if dies and len(dies) > 0:
            return dies[0]

    def get_abbrev_set(self):
        if self.abbrev_set is None:
            debug_abbrev = self.debug_info.dwarf.get_debug_abbrev()
            self.abbrev_set = debug_abbrev.get_abbrev_set(self.abbrev_offset)
        return self.abbrev_set

    def lookup_die_by_address(self, address):
        die_ranges = self.get_die_ranges()
        return die_ranges.lookup_die_by_address(address)

    def lookup_row_by_address(self, address):
        line_table = self.get_line_table()
        return line_table.lookup_address(address)


class TypeUnit(CompileUnit):
    def __init__(self, debug_info):
        CompileUnit.__init__(self, debug_info)
        self.type_signature = None
        self.type_offset = None

    def __str__(self):
        return ('%s: Type Unit: length = 0x%8.8x, version = 0x%4.4x, '
                'abbrev_offset = 0x%8.8x, addr_size = 0x%2.2x, type_signature '
                '= 0x%16.16x, type_offset = 0x%8.8x (new TU at 0x%8.8x)') % (
                    get_color_offset(self.offset), self.length,
                    self.dwarf_info.version, self.abbrev_offset,
                    self.dwarf_info.addr_size, self.type_signature,
                    self.type_offset, self.get_next_cu_offset())

    def get_header_byte_size(self):
        cu_header_length = CompileUnit.get_header_byte_size(self)
        # Sizes below are: sizeof(type_signature) + sizeof(type_offset)
        if self.dwarf_info.dwarf_size == 8:
            return cu_header_length + 8 + 8
        else:
            return cu_header_length + 8 + 4

    def unpack(self, data):
        CompileUnit.unpack(self, data)
        self.type_signature = data.get_uint64()
        self.type_offset = data.get_uint_size(self.dwarf_info.dwarf_size)
        return self.is_valid()


class DebugInfo:
    def __init__(self, dwarf):
        self.dwarf = dwarf
        self.cus = None
        self.tus = None
        self.die_ranges = None

    def get_compile_units(self):
        if self.cus is None:
            self.cus = list()
            data = self.dwarf.debug_info_data
            cu = CompileUnit(self)
            while cu.unpack(data):
                self.cus.append(cu)
                data.seek(cu.get_next_cu_offset())
                cu = CompileUnit(self)
        return self.cus

    def get_type_units(self):
        if self.tus is None:
            self.tus = list()
            data = self.dwarf.debug_types_data
            if data:
                tu = TypeUnit(self)
                while tu.unpack(data):
                    self.tus.append(tu)
                    data.seek(tu.get_next_cu_offset())
                    tu = TypeUnit(self)
        return self.tus

    def get_compile_unit_with_path(self, cu_path):
        cus = self.get_compile_units()
        for cu in cus:
            if cu.get_path().endswith(cu_path):
                return cu
        return None

    def get_die_ranges(self):
        if self.die_ranges is None:
            self.die_ranges = DIERanges()
            cus = self.get_compile_units()
            for cu in cus:
                cu_die_ranges = cu.get_die_ranges()
                if cu_die_ranges:
                    self.die_ranges.ranges.extend(cu_die_ranges.ranges)
            self.die_ranges.sort()
        return self.die_ranges

    def get_compile_unit_with_offset(self, cu_offset):
        cus = self.get_compile_units()
        i = bisect.bisect_left(cus, cu_offset)
        if i < len(cus):
            return cus[i]
        else:
            return None

    def lookup_address_in_cu(self, cu, address):
        die = cu.lookup_die_by_address(address)
        if die:
            # find the deepest DIE that contains the address
            die = die.lookup_address(address)
            print('Found DIE 0x%8.8x that contains address 0x%8.8x in %s:' % (
                  die.offset, address, die.get_die_ranges()))
            die.dump_ancestry(show_all_attrs=True)
        row = cu.lookup_row_by_address(address)
        if row:
            print('Found line table entry and contains address 0x%8.8x:' % (
                  address))
            row.dump_lookup_results(cu.get_line_table().prologue)
        return die or row

    def lookup_address(self, address):
        debug_aranges = self.dwarf.get_debug_aranges()
        if debug_aranges:
            cu_offset = debug_aranges.get_cu_offset_for_address(address)
            if cu_offset >= 0:
                cu = self.get_compile_unit_with_offset(cu_offset)
                if self.lookup_address_in_cu(cu, address):
                    return True
        # .debug_aranges is only for functions, check again using our deeper
        # checks where we look for ourselves through all functions and globals
        cus = self.get_compile_units()
        for cu in cus:
            if self.lookup_address_in_cu(cu, address):
                return True
        return False

    def find_die_with_offset(self, offset):
        cu = self.get_compile_unit_containing_offset(offset)
        if cu:
            return cu.get_die_with_offset(offset)
        return None

    def find_dies_with_name(self, name):
        '''Find all DIEs with a given name by searching the debug info and
           the debug types. Returns a list of DIE objects.'''
        dies = list()
        cus = self.get_compile_units()
        for cu in cus:
            cu_dies = cu.find_dies_with_name(name)
            if cu_dies:
                dies.extend(cu_dies)
        tus = self.get_type_units()
        for tu in tus:
            tu_dies = tu.find_dies_with_name(name)
            if tu_dies:
                dies.extend(tu_dies)
        return dies

    def get_compile_unit_containing_offset(self, offset):
        cus = self.get_compile_units()
        for cu in cus:
            if cu.contains_offset(offset):
                return cu
        return None

    def dump_debug_info(self, verbose=False, f=sys.stdout):
        print >>f, '.debug_info\n'
        cus = self.get_compile_units()
        for cu in cus:
            cu.dump(verbose=verbose, max_depth=sys.maxint, f=f)

    def dump_debug_types(self, verbose=False, f=sys.stdout):
        tus = self.get_type_units()
        if tus:
            print >>f, '.debug_types\n'
            for tu in tus:
                tu.dump(verbose=verbose, max_depth=sys.maxint, f=f)

    def __str__(self):
        s = '.debug_info\n'
        for cu in self.cus:
            s += str(cu) + '\n'
        return s


eAtomTypeNULL = 0
# DIE offset, check form for encoding
eAtomTypeDIEOffset = 1
# DIE offset of the compiler unit header that contains the item in question
eAtomTypeCUOffset = 2
# DW_TAG_xxx value, should be encoded as DW_FORM_data1 (if no tags exceed 255)
# or DW_FORM_data2
eAtomTypeTag = 3
# Flags from enum NameFlags
eAtomTypeNameFlags = 4
# Flags from enum TypeFlags,
eAtomTypeTypeFlags = 5
# A 32 bit hash of the full qualified name (since all hash entries are
# basename only)
eAtomTypeQualNameHash = 6


class AppleHash:
    def __init__(self, data, prologue):
        self.data = data
        self.magic = 0
        self.version = 0
        self.hash_enum = 0
        self.bucket_count = 0
        self.prologue_length = 0
        self.prologue = prologue
        self.hash_indexes = None
        self.hashes = None
        self.offsets = None

        # Unpack the header
        self.magic = data.get_uint32()
        self.version = data.get_uint16()
        self.hash_enum = data.get_uint16()
        self.bucket_count = data.get_uint32()
        self.hashes_count = data.get_uint32()
        self.prologue_length = data.get_uint32()
        # Unpack the header
        if self.prologue:
            self.prologue.unpack(data)
        # Unpack the hash indexes, hashes and offsets
        self.hash_indexes = list()
        self.hashes = list()
        self.offsets = list()
        for i in range(self.bucket_count):
            self.hash_indexes.append(data.get_uint32())
        for i in range(self.hashes_count):
            self.hashes.append(data.get_uint32())
        for i in range(self.hashes_count):
            self.offsets.append(data.get_uint32())

    def lookup(self, name):
        actual_hash = AppleHash.hash(name)
        bucket_count = self.bucket_count
        bucket_idx = actual_hash % bucket_count
        idx = self.hash_indexes[bucket_idx]
        while 1:
            curr_hash = self.hashes[idx]
            if actual_hash == curr_hash:
                hash_data_offset = self.offsets[idx]
                self.data.seek(hash_data_offset)
                return self.prologue.extract_data(name, self.data)
            if (curr_hash % bucket_count) != bucket_idx:
                break
            idx += 1
        return None

    def get_all_names(self):
        names = list()
        for offset in self.offsets:
            self.prologue.get_names_from_hash_data(self.data, offset, names)
        return names

    def dump(self, f=sys.stdout):
        print >>f, '          magic = 0x%8.8x' % (self.magic)
        print >>f, '        version = 0x%4.4x' % (self.version)
        print >>f, '      hash_enum = 0x%8.8x' % (self.hash_enum)
        print >>f, '   bucket_count = 0x%8.8x (%u)' % (self.bucket_count,
                                                       self.bucket_count)
        print >>f, '   hashes_count = 0x%8.8x (%u)' % (self.hashes_count,
                                                       self.hashes_count)
        print >>f, 'prologue_length = 0x%8.8x' % (self.prologue_length)
        print >>f, 'prologue:'
        self.prologue.dump(f=f)
        for (i, hash_idx) in enumerate(self.hash_indexes):
            if hash_idx == 4294967295:
                print >>f, ' bucket[%u] = <EMPTY>' % (i)
            else:
                print >>f, ' bucket[%u] = hashes[%u]' % (i, hash_idx)
        for (i, offset) in enumerate(self.offsets):
            print >>f, ' hashes[%u] = 0x%8.8x' % (i, self.hashes[i])
            print >>f, 'offsets[%u] = 0x%8.8x' % (i, offset)
            if self.prologue:
                self.prologue.dump_hash_data(data=self.data, offset=offset,
                                             f=f)

    def __str__(self):
        output = StringIO.StringIO()
        self.dump(output)
        return output.getvalue()

    @classmethod
    def hash(cls, s):
        h = 5381
        for c in s:
            h = ((h << 5) + h) + ord(c)
        return h & 0xffffffff


class DWARFHash:
    class AtomType(dict_utils.Enum):
        enum = {
            'eAtomTypeNULL': eAtomTypeNULL,
            'eAtomTypeDIEOffset': eAtomTypeDIEOffset,
            'eAtomTypeCUOffset': eAtomTypeCUOffset,
            'eAtomTypeTag': eAtomTypeTag,
            'eAtomTypeNameFlags': eAtomTypeNameFlags,
            'eAtomTypeTypeFlags': eAtomTypeTypeFlags,
            'eAtomTypeQualNameHash': eAtomTypeQualNameHash,
        }

        def __init__(self, initial_value=0):
            dict_utils.Enum.__init__(self, initial_value, self.enum)

    class Atom:
        def __init__(self, type, form):
            self.type = DWARFHash.AtomType(type)
            self.form = Form(form)

        def dump(self, index, f=sys.stdout):
            print >>f, 'atom[%u] type = %s, form = %s' % (index, self.type,
                                                          self.form)

        def __str__(self):
            output = StringIO.StringIO()
            self.dump(output)
            return output.getvalue()

    class Data:
        def __init__(self):
            self.offset = 0
            self.name = None
            self.die_infos = None

        def unpack(self, name, prologue, data):
            self.offset = data.tell()
            self.name = None
            self.die_infos = None
            while 1:
                strp = data.get_uint32()
                if strp == 0:
                    return True
                count = data.get_uint32()
                curr_name = prologue.get_string(strp)
                if name is None:
                    name = curr_name
                if curr_name == name:
                    self.name = name
                    # We have a full match
                    self.die_infos = list()
                    for i in range(count):
                        die_info = DWARFHash.DIEInfo()
                        if die_info.unpack(prologue, data):
                            self.die_infos.append(die_info)
                    return True
                else:
                    # Skip the entry using the prologue
                    for i in range(count):
                        prologue.skip(data)
            return False

        def dump(self, f=sys.stdout):
            if self.name is None:
                print >>f, '0x%8.8x: <NULL>' % (self.offset)
            else:
                print >>f, '0x%8.8x: "%s"' % (self.offset, self.name)
            if self.die_infos:
                for die_info in self.die_infos:
                    die_info.dump(f=f)

        def __str__(self):
            output = StringIO.StringIO()
            self.dump(output)
            return output.getvalue()

    class DIEInfo:
        def __init__(self):
            self.offset = -1
            self.tag = None
            self.type_flags = -1
            self.qualified_name_hash = -1

        def unpack(self, prologue, data):
            if len(prologue.atoms) == 0:
                return False
            for atom in prologue.atoms:
                value = atom.form.extract_value(None, data, None)
                atom_enum = atom.type.get_enum_value()
                if atom_enum == eAtomTypeDIEOffset:
                    self.offset = prologue.die_base_offset + value
                elif atom_enum == eAtomTypeTag:
                    self.tag = Tag(value)
                elif atom_enum == eAtomTypeTypeFlags:
                    self.type_flags = value
                elif atom_enum == eAtomTypeQualNameHash:
                    self.qualified_name_hash = value
                else:
                    raise ValueError
            return True

        def dump(self, f=sys.stdout):
            print >>f, '    ',
            if self.offset >= 0:
                print >>f, '{0x%8.8x}' % (self.offset),
            if self.tag is not None:
                print >>f, '%s' % (self.tag),
            if self.type_flags >= 0:
                print >>f, 'type_flags = 0x%8.8x' % (self.type_flags),
            if self.qualified_name_hash >= 0:
                print >>f, 'qualified_hash = 0x%8.8x' % (

                        self.qualified_name_hash),
            print >>f

        def __str__(self):
            output = StringIO.StringIO()
            self.dump(output)
            return output.getvalue()

    class Prologue:
        def __init__(self, string_data):
            self.die_base_offset = 0
            self.string_data = string_data
            self.atoms = list()
            self.fixed_size = 0

        def unpack(self, data):
            self.die_base_offset = data.get_uint32()
            atom_count = data.get_uint32()
            self.fixed_size = 0
            for i in range(atom_count):
                atom = data.get_uint16()
                form = data.get_uint16()
                atom = DWARFHash.Atom(atom, form)
                if self.fixed_size >= 0:
                    form_size = atom.form.get_fixed_size()
                    if form_size >= 0:
                        self.fixed_size += form_size
                    else:
                        self.fixed_size = -1
                self.atoms.append(atom)

        def extract_data(self, name, data):
            d = DWARFHash.Data()
            if d.unpack(name, self, data):
                return d
            else:
                return None

        def skip(self, data):
            if self.fixed_size >= 0:
                data.seek(data.tell() + self.fixed_size)
            else:
                fixed_size = 0
                for atom in self.atoms:
                    size = self.form.get_fixed_size()
                    if size == -1:
                        print 'error: not a fixed size'
                        raise ValueError
                    fixed_size += size
                data.seek(data.tell() + fixed_size)

        def get_names_from_hash_data(self, data, offset, names):
            data.seek(offset)
            while 1:
                hash_data = self.extract_data(None, data)
                if hash_data.name is None:
                    break
                names.append(hash_data.name)

        def dump_hash_data(self, data, offset, f=sys.stdout):
            data.seek(offset)
            while 1:
                hash_data = self.extract_data(None, data)
                hash_data.dump(f=f)
                if hash_data.name is None:
                    break

        def dump(self, f=sys.stdout):
            print >>f, 'prologue.die_base_offset = 0x%8.8x' % (
                self.die_base_offset)
            for (i, atom) in enumerate(self.atoms):
                atom.dump(index=i, f=f)

        def __str__(self):
            output = StringIO.StringIO()
            self.dump(output)
            return output.getvalue()

        def get_string(self, strp):
            self.string_data.seek(strp)
            return self.string_data.get_c_string()


class DWARF:
    '''DWARF parsing code'''
    def __init__(self,
                 debug_abbrev_data=None,
                 debug_aranges_data=None,
                 debug_info_data=None,
                 debug_line_data=None,
                 debug_ranges_data=None,
                 debug_str_data=None,
                 apple_names_data=None,
                 apple_types_data=None,
                 debug_types_data=None):
        self.debug_abbrev_data = debug_abbrev_data
        self.debug_aranges_data = debug_aranges_data
        self.debug_info_data = debug_info_data
        self.debug_line_data = debug_line_data
        self.debug_ranges_data = debug_ranges_data
        self.debug_str_data = debug_str_data
        self.debug_types_data = debug_types_data
        self.apple_names_data = apple_names_data
        self.apple_types_data = apple_types_data
        self.debug_abbrev = None
        self.debug_aranges = None
        self.debug_info = None
        self.debug_ranges = None
        self.apple_names = None
        self.apple_types = None

    def get_apple_names(self):
        if self.apple_names_data and self.apple_names is None:
            self.apple_names = AppleHash(
                self.apple_names_data, DWARFHash.Prologue(self.debug_str_data))
        return self.apple_names

    def get_apple_types(self):
        if self.apple_types_data and self.apple_types is None:
            self.apple_types = AppleHash(
                self.apple_types_data, DWARFHash.Prologue(self.debug_str_data))
        return self.apple_types

    def get_debug_abbrev(self):
        if self.debug_abbrev is None and self.debug_abbrev_data:
            self.debug_abbrev = DebugAbbrev()
            self.debug_abbrev.unpack(self.debug_abbrev_data)
        return self.debug_abbrev

    def get_compile_units(self):
        debug_info = self.get_debug_info()
        if debug_info:
            return debug_info.get_compile_units()
        return list()

    def get_type_units(self):
        debug_info = self.get_debug_info()
        if debug_info:
            return debug_info.get_type_units()
        return list()

    def get_debug_info(self):
        if self.debug_info is None and self.debug_info_data:
            self.debug_info = DebugInfo(self)
        return self.debug_info

    def get_debug_ranges(self):
        if self.debug_ranges is None and self.debug_ranges_data:
            self.debug_ranges = DebugRanges(self)
        return self.debug_ranges

    def get_debug_aranges(self):
        if self.debug_aranges is None and self.debug_aranges_data:
            self.debug_aranges = DebugAranges()
            self.debug_aranges_data.seek(0)
            self.debug_aranges.unpack(self.debug_aranges_data)
        return self.debug_aranges


class StringTable:
    '''A string table that uniques strings and hands out offsets'''
    def __init__(self):
        self.bytes = "\0"
        self.lookup = dict()

    def add(self, s):
        if s in self.lookup:
            return self.lookup[s]
        else:
            offset = len(self.bytes)
            self.lookup[s] = offset
            self.bytes += s + "\0"
            return offset

    def dump(self):
        for (i, byte) in enumerate(self.bytes):
            if i % 32 == 0:
                offset_str = "0x%8.8x:" % (i)
                print offset_str,
            print binascii.hexlify(byte),
        print


class DWARFGenerator:
    '''Classes to generate DWARF debug information.'''
    def __init__(self, dwarf_info):
        self.dwarf_info = dwarf_info
        self.compile_units = list()
        self.abbrevs = AbbrevSet()
        self.ranges = list()
        self.debug_abbrev = self.create_encoder()
        self.debug_aranges = self.create_encoder()
        self.debug_info = self.create_encoder()
        self.debug_line = self.create_encoder()
        self.debug_ranges = self.create_encoder()
        self.strtab = StringTable()
        self.did_generate = False

    def create_encoder(self):
        return file_extract.FileEncode(StringIO.StringIO(),
                                       self.dwarf_info.byte_order,
                                       self.dwarf_info.addr_size)

    def get_debug_abbrev_bytes(self):
        '''Get the .debug_abbrev bytes as a python string.'''
        return self.debug_abbrev.file.getvalue()

    def get_debug_aranges_bytes(self):
        '''Get the .debug_aranges bytes as a python string.'''
        return self.debug_aranges.file.getvalue()

    def get_debug_info_bytes(self):
        '''Get the .debug_info bytes as a python string.'''
        return self.debug_info.file.getvalue()

    def get_debug_line_bytes(self):
        '''Get the .debug_lime bytes as a python string.'''
        return self.debug_line.file.getvalue()

    def get_debug_ranges_bytes(self):
        '''Get the .debug_ranges bytes as a python string.'''
        return self.debug_ranges.file.getvalue()

    def get_debug_str_bytes(self):
        '''Get the .debug_str bytes as a python string.'''
        return self.strtab.bytes

    def addCompileUnit(self, tag):
        cu = DWARFGenerator.CompileUnit(self, tag)
        self.compile_units.append(cu)
        return cu

    def generate(self):
        if self.did_generate:
            return  # Can only generate once.
        self.did_generate = True
        # When generating DWARF we must first run through all DWARF
        # compile units and DIEs and let them figure out their offsets
        # since we might have one DIE attribute that is a reference to
        # another DIE and we must have all DIEs having their final
        # offsets before we try to emit the DWARF.
        offset = 0
        for cu in self.compile_units:
            offset = cu.prepare_for_encoding(offset)

        # Now emit all of the abbreviations in the .debug_abbrev section
        self.abbrevs.encode(self.debug_abbrev)
        # Emit all required info to all required sections for the CU itself
        # and all of its DIEs
        for cu in self.compile_units:
            cu.encode()

    def save(self, filename):
        self.generate()
        command = 'echo "" | clang -Wl,-r -x c -o "%s"' % (filename)
        remove_files = list()
        # Save the DWARF that was generated with a previous call to generate.
        debug_abbrev_bytes = self.get_debug_abbrev_bytes()
        if len(debug_abbrev_bytes):
            debug_abbrev_file = tempfile.NamedTemporaryFile(delete=False)
            debug_abbrev_file.write(debug_abbrev_bytes)
            debug_abbrev_file.close()
            remove_files.append(debug_abbrev_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_abbrev,%s' % (
                debug_abbrev_file.name)

        debug_aranges_bytes = self.get_debug_aranges_bytes()
        if len(debug_aranges_bytes):
            debug_aranges_file = tempfile.NamedTemporaryFile(delete=False)
            debug_aranges_file.write(debug_aranges_bytes)
            debug_aranges_file.close()
            remove_files.append(debug_aranges_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_aranges,%s' % (
                debug_aranges_file.name)

        debug_info_bytes = self.get_debug_info_bytes()
        if len(debug_info_bytes):
            debug_info_file = tempfile.NamedTemporaryFile(delete=False)
            debug_info_file.write(debug_info_bytes)
            debug_info_file.close()
            remove_files.append(debug_info_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_info,%s' % (
                debug_info_file.name)

        debug_line_bytes = self.get_debug_line_bytes()
        if len(debug_line_bytes):
            debug_line_file = tempfile.NamedTemporaryFile(delete=False)
            debug_line_file.write(debug_line_bytes)
            debug_line_file.close()
            remove_files.append(debug_line_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_line,%s' % (
                debug_line_file.name)

        debug_ranges_bytes = self.get_debug_ranges_bytes()
        if len(debug_ranges_bytes):
            debug_ranges_file = tempfile.NamedTemporaryFile(delete=False)
            debug_ranges_file.write(debug_ranges_bytes)
            debug_ranges_file.close()
            remove_files.append(debug_ranges_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_ranges,%s' % (
                debug_ranges_file.name)

        debug_str_bytes = self.get_debug_str_bytes()
        if len(debug_str_bytes):
            debug_str_file = tempfile.NamedTemporaryFile(delete=False)
            debug_str_file.write(debug_str_bytes)
            debug_str_file.close()
            remove_files.append(debug_str_file.name)
            command += ' -Wl,-sectcreate,__DWARF,__debug_str,%s' % (
                debug_str_file.name)

        # Need at least .debug_abbrev and .debug_info to make a DWARF file.
        if len(debug_abbrev_bytes) and len(debug_info_bytes):
            command += ' -'
            print '%s' % (command)
            (status, output) = commands.getstatusoutput(command)
            if output:
                print output
            if status != 0:
                print 'error: %u' % (status)
            else:
                print 'success'
        else:
            print 'error: no .debug_abbrev or .debug_info bytes'

        for path in remove_files:
            os.remove(path)

    def get_dwarf(self):
        self.generate()
        byte_order = self.dwarf_info.byte_order
        addr_size = self.dwarf_info.addr_size
        debug_abbrev = file_extract.FileExtract(StringIO.StringIO(
            self.get_debug_abbrev_bytes()), byte_order, addr_size)
        debug_info = file_extract.FileExtract(StringIO.StringIO(
            self.get_debug_info_bytes()), byte_order, addr_size)
        debug_line = file_extract.FileExtract(StringIO.StringIO(
            self.get_debug_line_bytes()), byte_order, addr_size)
        debug_ranges = file_extract.FileExtract(StringIO.StringIO(
            self.get_debug_ranges_bytes()), byte_order, addr_size)
        debug_str = file_extract.FileExtract(StringIO.StringIO(
            self.get_debug_str_bytes()), byte_order, addr_size)
        return DWARF(debug_abbrev_data=debug_abbrev,
                     debug_info_data=debug_info,
                     debug_line_data=debug_line,
                     debug_ranges_data=debug_ranges,
                     debug_str_data=debug_str)

    class CompileUnit:
        '''DWARF generator compile unit'''
        def __init__(self, generator, tag):
            self.offset = -1
            self.length = -1
            self.dwarf_info = generator.dwarf_info
            self.generator = generator
            self.die = DWARFGenerator.DIE(self, tag)
            self.prologue = LineTable.Prologue(self)
            self.prologue.generate_init()
            self.line_rows = list()
            self.aranges = None
            self.die_ranges = None

        def get_die_ranges(self):
            if self.die_ranges is None:
                self.die_ranges = AddressRangeList()
                for die in self.die.children:
                    die_ranges = die.get_die_ranges()
                    if die_ranges:
                        self.die_ranges.ranges.extend(die_ranges.ranges)
                if len(self.die_ranges):
                    self.die_ranges.finalize()
            return self.die_ranges

        def generate_debug_aranges(self):
            '''Auto generate the .debug_aranges by looking at all
               DW_TAG_subprogram DIEs and using their ranges.'''
            self.get_aranges().address_ranges = self.get_die_ranges()

        def generate_cu_ranges(self):
            '''Auto generate the .debug_aranges by looking at all
               DW_TAG_subprogram DIEs and using their ranges.'''
            ranges = copy.deepcopy(self.get_die_ranges())
            if len(ranges):
                base_addr = ranges.get_min_address()
                if base_addr >= 0:
                    self.die.addAttribute(DW_AT_low_pc, DW_FORM_addr,
                                          base_addr)
                    # Make all of the range information relative to the
                    # compile unit base address
                    for range in ranges:
                        range.lo -= base_addr
                        range.hi -= base_addr
                if ranges:
                    self.die.addAttribute(DW_AT_ranges, DW_FORM_sec_offset,
                                          ranges)

        def get_aranges(self):
            if self.aranges is None:
                self.aranges = DebugAranges.Set(self.dwarf_info)
            return self.aranges

        def add_arange(self, low_pc, high_pc):
            '''Manually add a range to the .debug_aranges'''
            self.get_aranges().append_range(low_pc, high_pc)

        def add_line_entry(self, fullpath, line, addr, end_sequence=False):
            row = LineTable.Row(self.prologue)
            row.range.lo = addr
            row.file = self.prologue.add_file(fullpath)
            row.line = line
            row.end_sequence = end_sequence
            self.line_rows.append(row)

        def prepare_for_encoding(self, offset):
            dwarf32 = self.dwarf_info.isDWARF32()
            # We must emit the line tables first so we know the value of the
            # DW_AT_stmt_list and add the attribue. We only need to emit a line
            # table if we have files in the prologue. If we don't have any
            # files, then we don't have a line table of anything that requires
            # the line table (DW_AT_decl_file or DW_AT_call_file).
            if len(self.prologue.files) > 0:
                debug_line = self.generator.debug_line
                self.prologue.encode(debug_line)
                prev_row = None
                for row in self.line_rows:
                    row.encode(debug_line, prev_row)
                    prev_row = row
                # Fixup the prologue length field after writing all rows.
                line_table_length = debug_line.tell() - (
                    self.prologue.offset + 4)
                debug_line.fixup_uint_size(4, line_table_length,
                                           self.prologue.offset)
                # Add a DW_AT_stmt_list to the compile unit DIE with the
                # right offset
                self.die.addSectionOffsetAttribute(DW_AT_stmt_list,
                                                   self.prologue.offset)

            # Now calculate the CU offset and let each DIE calculate its offset
            # so we can correctly emit relative and absolute DIE references in
            # the self.encode(...) later. This compile unit might contain DIEs
            # that refer to DIEs in previous compile units, this compile unit,
            # or subsequent compile units.
            self.offset = offset
            if dwarf32:
                cu_rel_offset = 11
            else:
                cu_rel_offset = 11 + 8
            cu_rel_end_offset = self.die.computeSizeAndOffsets(cu_rel_offset)
            offset += cu_rel_end_offset
            self.length = cu_rel_end_offset - 4
            return offset  # return the offset for the next CU

        def encode(self):
            debug_info = self.generator.debug_info
            actual_offset = debug_info.file.tell()
            if actual_offset != self.offset:
                print('error: compile unit actual offset is 0x%x when it '
                      'should be 0x%x' % (actual_offset, self.offset))
            # Encode the compile unit header
            debug_info.put_uint32(self.length)
            debug_info.put_uint16(self.dwarf_info.version)
            if self.dwarf_info.version <= 4:
                debug_info.put_uint32(0)  # Abbrev offset
                debug_info.put_uint8(self.dwarf_info.addr_size)
            else:
                # Unit type for DWARF 5 and later
                debug_info.put_uint8(DW_UT_compile)
                debug_info.put_uint8(self.dwarf_info.addr_size)
                debug_info.put_uint32(0)  # Abbrev offset
            # Encode all DIEs and their attribute
            self.die.encode(debug_info)

            # Encode the .debug_aranges if any
            if self.aranges:
                self.aranges.cu_offset = self.offset
                self.aranges.encode(self.generator.debug_aranges)

    class Attribute:
        '''DWARF generator DIE attribute'''
        def __init__(self, attr, form, value):
            self.attr_spec = AttributeSpec(attr, form)
            self.value = value

        def get_form(self):
            return self.attr_spec.form.get_enum_value()

        def get_attr(self):
            return self.attr_spec.attr.get_enum_value()

        def encode(self, die, data):
            form = self.attr_spec.form.get_enum_value()
            value = self.value
            if isinstance(self.value, AddressRangeList):
                value = self.value.encode(die.cu.generator.debug_ranges)

            if form == DW_FORM_strp:
                if isinstance(value, basestring):
                    stroff = die.cu.generator.strtab.add(value)
                else:
                    stroff = value
                data.put_uint32(stroff)
            elif form == DW_FORM_addr:
                data.put_address(value)
            elif form == DW_FORM_data1:
                data.put_uint8(value)
            elif form == DW_FORM_data2:
                data.put_uint16(value)
            elif form == DW_FORM_data4:
                data.put_uint32(value)
            elif form == DW_FORM_data8:
                data.put_uint64(value)
            elif form == DW_FORM_udata:
                data.put_uleb128(value)
            elif form == DW_FORM_sdata:
                data.put_sleb128(value)
            elif form == DW_FORM_string:
                data.put_c_string(value)
            elif form == DW_FORM_block1:
                data.put_uint8(len(value))
                if isinstance(value, list):
                    for u8 in value:
                        data.put_uint8(u8)
                else:
                    data.file.write(value)
            elif form == DW_FORM_block2:
                data.put_uint16(len(value))
                data.file.write(value)
            elif form == DW_FORM_block4:
                data.put_uint32(len(value))
                data.file.write(value)
            elif form == DW_FORM_block:
                data.put_uleb128(len(value))
                data.file.write(value)
            elif form == DW_FORM_exprloc:
                data.put_uleb128(len(value))
                data.file.write(value)
            elif form == DW_FORM_flag:
                if value:
                    data.put_uint8(1)
                else:
                    data.put_uint8(0)
            elif form == DW_FORM_ref1:
                if isinstance(value, DWARFGenerator.DIE):
                    data.put_uint8(value.getCompileUnitOffset())
                else:
                    data.put_uint8(value)
            elif form == DW_FORM_ref2:
                if isinstance(value, DWARFGenerator.DIE):
                    data.put_uint16(value.getCompileUnitOffset())
                else:
                    data.put_uint16(value)
            elif form == DW_FORM_ref4:
                if isinstance(value, DWARFGenerator.DIE):
                    data.put_uint32(value.getCompileUnitOffset())
                else:
                    data.put_uint32(value)
            elif form == DW_FORM_ref8:
                if isinstance(value, DWARFGenerator.DIE):
                    data.put_uint64(value.getCompileUnitOffset())
                else:
                    data.put_uint64(value)
            elif form == DW_FORM_ref_udata:
                if isinstance(value, DWARFGenerator.DIE):
                    data.put_uleb128(value.getCompileUnitOffset())
                else:
                    data.put_uleb128(value)
                data.put_uleb128(value)
            elif form == DW_FORM_sec_offset:
                int_size = self.attr_spec.form.get_fixed_size(
                    die.cu.dwarf_info)
                data.put_uint_size(int_size, value)
            elif form == DW_FORM_flag_present:
                pass
            elif form == DW_FORM_ref_sig8:
                data.put_uint64(value)
            elif form == DW_FORM_ref_addr:
                int_size = self.attr_spec.form.get_fixed_size(
                    die.cu.dwarf_info)
                if isinstance(value, DWARFGenerator.DIE):
                    data.put_uint_size(int_size, value.getOffset())
                else:
                    data.put_uint_size(int_size, value)
            elif form == DW_FORM_indirect:
                raise ValueError("DW_FORM_indirect isn't handled")

    class DIE:
        '''DWARF generator DIE (debug information entry)'''
        def __init__(self, cu, tag):
            self.offset = -1
            self.abbrev_code = -1
            self.cu = cu
            self.tag = tag
            self.attributes = list()
            self.children = list()

        def getCompileUnitOffset(self):
            '''Get the compile unit relative offset for this DIE'''
            if self.offset == -1:
                raise ValueError("DIE hasn't had its size calculated yet")
            return self.offset

        def getOffset(self):
            '''Get the absolute offset within all DWARF for this DIE'''
            if self.cu.offset == -1:
                raise ValueError("DIE's compile unit hasn't had its size "
                                 "calculated yet")
            return self.cu.offset + self.getCompileUnitOffset()

        def addAttribute(self, attr, form, value):
            attr = DWARFGenerator.Attribute(attr, form, value)
            self.attributes.append(attr)
            return attr

        def addSectionOffsetAttribute(self, attr, value):
            '''Correctly encode an attribute with the right DW_FORM for the
               current DWARF version.'''
            if self.cu.dwarf_info.version >= 4:
                self.addAttribute(attr, DW_FORM_sec_offset, value)
            elif self.cu.dwarf_info.isDWARF32():
                self.addAttribute(attr, DW_FORM_data4, value)
            else:
                self.addAttribute(attr, DW_FORM_data8, value)

        def addChild(self, tag):
            die = DWARFGenerator.DIE(self.cu, tag)
            self.children.append(die)
            return die

        def createAbbrevDecl(self):
            abbrev = AbbrevDecl()
            abbrev.tag = self.tag
            abbrev.has_children = len(self.children) > 0
            for attr in self.attributes:
                abbrev.attribute_specs.append(attr.attr_spec)
            return abbrev

        def computeSizeAndOffsets(self, offset):
            self.offset = offset
            self.abbrev_code = self.cu.generator.abbrevs.getCode(
                self.createAbbrevDecl())
            offset += get_uleb128_byte_size(self.abbrev_code)
            for attr in self.attributes:
                byte_size = attr.attr_spec.form.get_byte_size(self, attr.value)
                offset += byte_size
            if self.children:
                for child in self.children:
                    offset = child.computeSizeAndOffsets(offset)
                offset += 1  # NULL tag to terminate children
            return offset

        def encode(self, encoder):
            actual_offset = encoder.file.tell()
            if actual_offset != self.offset:
                print('error: DIE actual offset is 0x%x when it should be 0x%x'
                      % (actual_offset, self.offset))
            encoder.put_uleb128(self.abbrev_code)
            for attr in self.attributes:
                attr.encode(self, encoder)
            if self.children:
                for child in self.children:
                    child.encode(encoder)
                encoder.put_uleb128(0)  # Terminate child DIE chain

        def get_die_ranges(self):
            ranges = None
            if self.tag == DW_TAG_subprogram:
                lo_pc = None
                hi_pc = None
                hi_pc_is_offset = False
                for attribute in self.attributes:
                    attr = attribute.get_attr()
                    if attr == DW_AT_low_pc:
                        lo_pc = attribute.value
                    elif attr == DW_AT_high_pc:
                        hi_pc = attribute.value
                        if attribute.get_form() != DW_FORM_addr:
                            hi_pc_is_offset = True
                    elif attr == DW_AT_ranges:
                        if isinstance(attribute.value, AddressRangeList):
                            if ranges is None:
                                ranges = AddressRangeList()
                            ranges.append(attribute.value)
                        else:
                            raise ValueError
                if lo_pc is None and hi_pc is None:
                    return
                if hi_pc_is_offset:
                    hi_pc += lo_pc
                if ranges is None:
                    ranges = AddressRangeList()
                ranges.append(AddressRange(lo_pc, hi_pc))
            if self.children:
                for child in self.children:
                    child_ranges = child.get_die_ranges()
                    if child_ranges:
                        if ranges is None:
                            ranges = AddressRangeList()
                        ranges.append(child_ranges)
            return ranges


def append_dwarf_options(parser):
    '''Add DWARF options to object file options to allow ELF, MachO and any
       other object files to have a consistent command line interface when
       dumping DWARF'''
    group = optparse.OptionGroup(
        parser,
        "DWARF Options",
        "Options for dumping DWARF debug information.")
    # group.add_option("-g", action="store_true", help="Group option.")
    group.add_option(
        '--debug-all',
        action='store_true',
        dest='debug_all',
        help='Dump all .debug_* sections',
        default=False)
    group.add_option(
        '--debug-abbrev',
        action='store_true',
        dest='debug_abbrev',
        help='Dump the .debug_abbrev section',
        default=False)
    group.add_option(
        '--debug-aranges',
        action='store_true',
        dest='debug_aranges',
        help='Dump the .debug_aranges section',
        default=False)
    group.add_option(
        '--debug-info',
        action='store_true',
        dest='debug_info',
        help='Dump the .debug_info section',
        default=False)
    group.add_option(
        '--debug-line',
        action='store_true',
        dest='debug_line',
        help='Dump the .debug_line section',
        default=False)
    group.add_option(
        '--debug-map',
        action='store_true',
        dest='debug_map',
        help='Dump the address map of all DWARF',
        default=False)
    group.add_option(
        '--debug-types',
        action='store_true',
        dest='debug_types',
        help='Dump the .debug_types section',
        default=False)
    group.add_option(
        '--apple-names',
        action='store_true',
        dest='apple_names',
        help='Dump the .apple_names section',
        default=False)
    group.add_option(
        '--apple-types',
        action='store_true',
        dest='apple_types',
        help='Dump the .apple_types section',
        default=False)
    group.add_option(
        '--compile-unit',
        type='string',
        action='append',
        dest='cu_names',
        help='Dump a compile unit by file basename or full path.')
    group.add_option(
        '-q', '--dwarf-query',
        type='string',
        action='append',
        dest='dwarf_queries',
        help='Create a SQL .')
    group.add_option(
        '--die',
        type='int',
        action='append',
        dest='die_offsets',
        help='Dump the specified DIE by DIE offset.')
    group.add_option(
        '--variable-size',
        action='store_true',
        dest='variable_size',
        help='Use with --die to show the byte size of all variables in a DIE.',
        default=False)
    group.add_option(
        '--address',
        action='append',
        type='int',
        dest='lookup_addresses',
        help='Address to lookup')
    group.add_option(
        '--name',
        action='append',
        type='string',
        dest='lookup_names',
        help='Name to lookup in .debug_info or .debug_types.')
    group.add_option(
        '-C', '--color',
        action='store_true',
        dest='color',
        default=False,
        help='Enable colorized output')
    parser.add_option_group(group)


def dump_die_variables(die):
    total_byte_size = 0
    if tag_is_variable(die.get_tag()):
        type_die = die.get_attribute_value_as_die(DW_AT_type)
        if type_die:
            byte_size = die.get_byte_size()
            if byte_size > 0:
                print '0x%8.8x: <%5u> %s' % (die.get_offset(), byte_size,
                                             die.get_name())
                total_byte_size += byte_size
    child = die.get_child()
    while child:
        total_byte_size += dump_die_variables(child)
        child = child.get_sibling()
    return total_byte_size


def have_dwarf_options(options):
    return (options.debug_all
            or options.debug_abbrev
            or options.debug_aranges
            or options.debug_info
            or options.debug_line
            or options.debug_types
            or options.lookup_addresses
            or options.lookup_names
            or options.cu_names
            or options.die_offsets
            or options.apple_names
            or options.apple_types
            or options.debug_map)


def handle_dwarf_options(options, objfile, f=sys.stdout):
    if have_dwarf_options(options):
        if options.debug_all:
            options.debug_abbrev = True
            options.debug_aranges = True
            options.debug_info = True
            options.debug_line = True
            options.debug_types = True

        dwarf = objfile.get_dwarf()
        if dwarf:
            if options.debug_abbrev:
                debug_abbrev = dwarf.get_debug_abbrev()
                print debug_abbrev
            if options.debug_aranges:
                debug_aranges = dwarf.get_debug_aranges()
                print debug_aranges
            debug_info = dwarf.get_debug_info()
            if debug_info:
                if options.lookup_names:
                    for name in options.lookup_names:
                        dies = debug_info.find_dies_with_name(name)
                        if dies:
                            print >>f, "DIEs with name '%s':" % (name)
                            for die in dies:
                                die.dump_ancestry(verbose=options.verbose,
                                                  show_all_attrs=True, f=f)
                        else:
                            print >>f, "No DIEs with name '%s'" % (name)
                if options.debug_info:
                    debug_info.dump_debug_info(verbose=options.verbose, f=f)
                if options.debug_types:
                    debug_info.dump_debug_types(verbose=options.verbose, f=f)
                if options.debug_map:
                    die_ranges = debug_info.get_die_ranges()
                    if die_ranges:
                        print die_ranges
                if options.lookup_addresses:
                    for address in options.lookup_addresses:
                        print 'lookup 0x%8.8x' % (address)
                        result = debug_info.lookup_address(address)
                        pprint.PrettyPrinter(indent=4).pprint(result)
                if options.cu_names:
                    for cu_name in options.cu_names:
                        cu = debug_info.get_compile_unit_with_path(cu_name)
                        if cu:
                            print cu.get_die()
                            line_table = cu.get_line_table()
                            line_table.dump(verbose=options.verbose)
                if options.debug_line:
                    cus = debug_info.get_compile_units()
                    for cu in cus:
                        line_table = cu.get_line_table()
                        line_table.dump(verbose=options.verbose)
                if options.die_offsets:
                    for die_offset in options.die_offsets:
                        die = debug_info.find_die_with_offset(die_offset)
                        if die:
                            if options.variable_size:
                                size = dump_die_variables(die)
                                print '0x%8.8x: total variable size is %u' % (
                                    die_offset, size)
                            else:
                                die.dump(verbose=options.verbose,
                                         show_all_attrs=True)
                        else:
                            print('error: no DIE for .debug_info offset '
                                  '0x%8.8x' % (die_offset))
                if options.apple_names:
                    apple_names = dwarf.get_apple_names()
                    print apple_names
                if options.apple_types:
                    apple_types = dwarf.get_apple_types()
                    print apple_types
            else:
                print 'error: no .debug_info'
        else:
            print 'error: no DWARF in "%s"' % (objfile.path)


def main():
    args = ['colorize', 'dwarfdump']
    args.extend(sys.argv[1:])
    print subprocess.check_output(args)


if __name__ == '__main__':
    main()
