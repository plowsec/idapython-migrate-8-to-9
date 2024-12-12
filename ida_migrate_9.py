import ast
import sys
from typing import Dict, List, Tuple
from pathlib import Path
class IdaPythonMigrationChecker:
    """Checks Python code for IDA API changes between v8.4 and v9.0"""

    def __init__(self):

        self.moved_classes: Dict[str, str] = {
            'ida_graph.node_ordering_t': 'ida_gdl.node_ordering_t',
            'ida_graph.edge_t': 'ida_gdl.edge_t',
            'ida_graph.edgevec_t': 'ida_gdl.edgevec_t',
            'ida_kernwin.enumplace_t': 'Removed - no direct replacement',
            'ida_kernwin.structplace_t': 'Removed - no direct replacement',
        }

        self.renamed_classes: Dict[str, str] = {
            'ida_graph.abstract_graph_t': 'drawable_graph_t',
            'ida_graph.mutable_graph_t': 'interactive_graph_t',
        }

        # Removed functions by module
        self.removed_funcs: Dict[str, str] = {
            # ida_typeinf removals
            'ida_typeinf.callregs_t_regcount': 'Use callregs_t methods instead',
            'ida_typeinf.get_ordinal_from_idb_type': 'No direct replacement',
            'ida_typeinf.is_autosync': 'No direct replacement',
            'ida_typeinf.get_udm_tid': 'Use tinfo_t.get_udm_tid instead',
            'ida_typeinf.get_tinfo_tid': 'Use tinfo_t.get_tid instead',
            'ida_typeinf.tinfo_t_get_stock': 'No direct replacement',
            'ida_typeinf.get_ordinal_qty': 'Use ida_typeinf.get_ordinal_count or ida_typeinf.get_ordinal_limit',
            'ida_typeinf.import_type': 'Use idc.import_type instead',

            # ida_frame removals
            'ida_frame.get_stkvar': 'Use tinfo_t methods instead',
            'ida_frame.get_frame': 'Use tinfo_t.get_func_frame instead',
            'ida_frame.get_frame_member_by_id': 'No direct replacement',
            'ida_frame.get_min_spd_ea': 'No direct replacement',
            'ida_frame.delete_unreferenced_stkvars': 'No direct replacement',
            'ida_frame.delete_wrong_stkvar_ops': 'No direct replacement',

            # ida_bytes removals
            'ida_bytes.free_chunck': 'No direct replacement',
            'ida_bytes.get_8bit': 'No direct replacement',

            # ida_dirtree removals
            'ida_dirtree.dirtree_cursor_root_cursor': 'Use alternative dirtree navigation methods',
            'ida_dirtree.dirtree_t_errstr': 'No direct replacement',

            # ida_diskio removals
            'ida_diskio.enumerate_files2': 'No direct replacement',
            'ida_diskio.eclose': 'No direct replacement',

            # ida_hexrays removals
            'ida_hexrays.get_member_type': 'Use tinfo_t methods instead',
            'ida_hexrays.checkout_hexrays_license': 'No direct replacement',
            'ida_hexrays.cinsn_t_insn_is_epilog': 'No direct replacement',

            # ida_kernwin removals
            'ida_kernwin.place_t_as_enumplace_t': 'Use alternative place_t methods',
            'ida_kernwin.place_t_as_structplace_t': 'Use alternative place_t methods',
            'ida_kernwin.open_enums_window': 'No direct replacement',
            'ida_kernwin.open_structs_window': 'No direct replacement',
            'ida_kernwin.choose_struc': 'No direct replacement',
            'ida_kernwin.choose_enum': 'No direct replacement',
            'ida_kernwin.choose_enum_by_value': 'No direct replacement',

            # ida_lines removals
            'ida_lines.set_user_defined_prefix': 'No direct replacement',

            # ida_nalt removals
            'ida_nalt.validate_idb_names': 'No direct replacement',

            # ida_pro removals
            'ida_pro.uchar_array_frompointer': 'Use new pointer classes',
            'ida_pro.tid_array_frompointer': 'Use new pointer classes',
            'ida_pro.ea_array_frompointer': 'Use new pointer classes',
            'ida_pro.sel_array_frompointer': 'Use new pointer classes',
            'ida_pro.int_pointer_frompointer': 'Use new pointer classes',
            'ida_pro.sel_pointer_frompointer': 'Use new pointer classes',
            'ida_pro.ea_pointer_frompointer': 'Use new pointer classes',

            # ida_registry removals
            'ida_registry.reg_load': 'No direct replacement',
            'ida_registry.reg_flush': 'No direct replacement',

            # ida_search removals
            'ida_search.find_binary': 'Use ida_bytes.find_bytes instead',
            'ida_search.find_text': 'Use ida_bytes.find_string instead',

            # ida_ua removals
            'ida_ua.construct_macro': 'Use macro_constructor_t.construct_macro instead',

            # ida_graph removals (moved to ida_gdl)
            'ida_graph.node_ordering_t': 'Use ida_gdl.node_ordering_t',
            'ida_graph.edge_t': 'Use ida_gdl.edge_t',
            'ida_graph.edgevec_t': 'Use ida_gdl.edgevec_t',

            # ida_regfinder removals
            'ida_regfinder.reg_value_info_t_make_dead_end': 'Use reg_value_info_t methods',
            'ida_regfinder.reg_value_info_t_make_aborted': 'Use reg_value_info_t methods',
            'ida_regfinder.reg_value_info_t_make_badinsn': 'Use reg_value_info_t methods',
            'ida_regfinder.reg_value_info_t_make_unkinsn': 'Use reg_value_info_t methods',
            'ida_regfinder.reg_value_info_t_make_unkfunc': 'Use reg_value_info_t methods',
            'ida_regfinder.reg_value_info_t_make_unkloop': 'Use reg_value_info_t methods',
            'ida_regfinder.reg_value_info_t_make_unkmult': 'Use reg_value_info_t methods',
            'ida_regfinder.reg_value_info_t_make_num': 'Use reg_value_info_t methods',
            'ida_regfinder.reg_value_info_t_make_initial_sp': 'Use reg_value_info_t methods',
        }

        # Removed class methods
        self.removed_methods: Dict[str, str] = {
            'enum_type_data_t.get_constant_group': 'Use enum_type_data_t.all_constants or all_groups',
            'vdui_t.set_strmem_type': 'No direct replacement',
            'vdui_t.rename_strmem': 'No direct replacement',
            'fpvalue_t._get_10bytes': 'No direct replacement',
            'fpvalue_t._set_10bytes': 'No direct replacement',
            'processor_t.get_uFlag': 'No direct replacement',
            '_processor_t.has_realcvt': 'No direct replacement',
        }

        # Modified function signatures
        self.modified_funcs: Dict[str, Tuple[str, str]] = {
            # ida_bytes modifications
            'ida_bytes.op_enum': ('ea: "ea_t", n: "int", id: "enum_t", serial: "uchar"=0',
                                'ea: "ea_t", n: "int", id: "tid_t", serial: "uchar"=0'),
            'ida_bytes.get_enum_id': ('ea: "ea_t", n: "int") -> "tid_t"',
                                    'ea: "ea_t", n: "int") -> "enum_t"'),
            'ida_bytes.parse_binpat_str': ('out: "compiled_binpat_vec_t", ea: "ea_t", _in: "char const *", radix: "int", strlits_encoding: "int"=0) -> "str"',
                                         'out: "compiled_binpat_vec_t", ea: "ea_t", _in: "char const *", radix: "int", strlits_encoding: "int"=0) -> "bool"'),
            'ida_bytes.bin_search3': ('start_ea: "ea_t", end_ea: "ea_t", data: "compiled_binpat_vec_t", flags: "int") -> "ea_t"',
                                    'start_ea: "ea_t", end_ea: "ea_t", data: "compiled_binpat_vec_t const &", flags: "int") -> "(ea_t, size_t)"'),

            # ida_hexrays modifications
            'ida_hexrays.save_user_labels2': ('func_ea: "ea_t", user_labels: "user_labels_t", func: "cfunc_t"=None) -> "void"',
                                            'func_ea: "ea_t", user_labels: "user_labels_t", func: "cfunc_t"=None) -> "void"'),
            
            # ida_idaapi modifications
            'ida_idaapi.get_inf_structure': ('', 'Use specific inf_get_* accessors instead'),

            # ida_regfinder modifications
            'ida_regfinder.invalidate_regfinder_cache': ('ea: "ea_t") -> "void"',
                                                       'from=BADADDR: "ea_t", to=BADADDR: "ea_t") -> "void"'),
        }

        # Renamed functions
        self.renamed_funcs: Dict[str, str] = {
            'ida_graph.create_mutable_graph': 'create_interactive_graph',
            'ida_graph.delete_mutable_graph': 'delete_interactive_graph',
            'ida_graph.grcode_create_mutable_graph': 'grcode_create_interactive_graph',
            'ida_struct.add_struc':'idc.add_struc',
        }

        self.struct_api_changes: Dict[str, str] = {
            # Direct replacements with idc module
            'add_struc': 'Use idc.add_struc instead',
            'add_struc_member': 'Use idc.add_struc_member instead',
            'del_struc': 'Use idc.del_struc instead',
            'del_struc_member': 'Use idc.del_struc_member instead',
            'expand_struc': 'Use idc.expand_struc instead',
            'get_member_cmt': 'Use idc.get_member_cmt instead',
            'get_member_id': 'Use idc.get_member_id instead',
            'get_member_name': 'Use idc.get_member_name instead',
            'get_member_size': 'Use idc.get_member_size instead',
            'get_struc_cmt': 'Use idc.get_struc_cmt instead',
            'get_struc_id': 'Use idc.get_struc_id instead',
            'get_struc_name': 'Use idc.get_struc_name instead',
            'get_struc_size': 'Use idc.get_struc_size instead',
            'is_member_id': 'Use idc.is_member_id instead',
            'is_union': 'Use idc.is_union instead',
            'set_member_cmt': 'Use idc.set_member_cmt instead',
            'set_member_name': 'Use idc.set_member_name instead',
            'set_member_type': 'Use idc.set_member_type instead',
            'set_struc_cmt': 'Use idc.set_struc_cmt instead',
            'set_struc_name': 'Use idc.set_struc_name instead',
            
            # Functions requiring custom implementation
            'del_struc_members': 'See documentation for example implementation',
            'get_best_fit_member': 'See documentation for example implementation',
            'get_first_struc_idx': 'See documentation for example implementation',
            'get_innermost_member': 'See documentation for example implementation',
            'get_last_struc_idx': 'Function removed in IDA 9.0',
            'get_max_offset': 'See documentation for example implementation',
            'get_member': 'See documentation for example implementation',
            'get_member_by_fullname': 'See documentation for example implementation',
            'get_member_by_id': 'Use tinfo_t.get_udm_by_tid instead',
            'get_member_by_name': 'See documentation for example implementation',
            'get_member_fullname': 'See documentation for example implementation',
            'get_member_struc': 'See documentation for example implementation',
            'get_member_tinfo': 'See documentation for example implementation',
            'get_next_member_idx': 'Function removed in IDA 9.0',
            'get_next_struc_idx': 'Function removed in IDA 9.0',
            'get_or_guess_member_tinfo': 'Function removed in IDA 9.0',
            'get_prev_member_idx': 'Function removed in IDA 9.0',
            'get_prev_struc_idx': 'Function removed in IDA 9.0',
            'get_sptr': 'See documentation for example implementation',
            'get_struc': 'See documentation for example implementation',
            'get_struc_by_idx': 'Function removed in IDA 9.0',
            'get_struc_first_offset': 'Function removed in IDA 9.0',
            'get_struc_idx': 'See documentation for example implementation',
            'get_struc_last_offset': 'Function removed in IDA 9.0',
            'get_struc_next_offset': 'Function removed in IDA 9.0',
            'get_struc_prev_offset': 'Function removed in IDA 9.0',
            'get_struc_qty': 'See documentation for example implementation',
            'is_anonymous_member_name': 'Use ida_frame.is_anonymous_member_name instead',
            'is_dummy_member_name': 'Use ida_frame.is_dummy_member_name instead',
            'is_special_member': 'See documentation for example implementation',
            'is_varmember': 'See documentation for example implementation',
            'is_varstr': 'See documentation for example implementation',
            'retrieve_member_info': 'Function removed in IDA 9.0',
            'save_struc': 'Use tinfo_t.save_type instead',
            'set_member_tinfo': 'Function removed in IDA 9.0',
            'set_struc_align': 'Function removed in IDA 9.0',
            'set_struc_hidden': 'Function removed in IDA 9.0',
            'set_struc_idx': 'Function removed in IDA 9.0',
            'set_struc_listed': 'See documentation for example implementation',
            'stroff_as_size': 'Use ida_typeinf.stroff_as_size instead',
            'struct_field_visitor_t': 'Use ida_typeinf.tinfo_visitor_t instead',
            'unsync_and_delete_struc': 'Function removed in IDA 9.0',
            'visit_stroff_fields': 'Function removed in IDA 9.0',
            'visit_stroff_udms': 'Use ida_typeinf.visit_stroff_udms instead'
        }

        # Add to existing removed_funcs dict
        self.removed_funcs.update(self.struct_api_changes)

        self.removed_class_members: Dict[str, Dict[str, str]] = {
            'member_t': {
                'by_til': 'Use ida_typeinf.udm_t.is_by_til instead',
                'eoff': 'No direct replacement',
                'flag': 'No direct replacement',
                'get_size': 'Use ida_typeinf.udm_t.size // 8 instead',
                'get_soff': 'Use soff or ida_typeinf.udm_t.offset // 8 instead',
                'has_ti': 'No direct replacement',
                'has_union': 'No direct replacement',
                'id': 'No direct replacement',
                'is_baseclass': 'Use ida_typeinf.udm_t.is_baseclass instead',
                'is_destructor': 'Use ida_typeinf.udm_t.can_be_dtor instead',
                'is_dupname': 'No direct replacement',
                'props': 'No direct replacement',
                'soff': 'Use ida_typeinf.udm_t.offset // 8 instead',
                'this': 'No direct replacement',
                'thisown': 'No direct replacement',
                'unimem': 'No direct replacement'
            },
            'struct_t': {
                'age': 'No direct replacement',
                'from_til': 'No direct replacement',
                'get_alignment': 'No direct replacement',
                'get_last_member': 'No direct replacement',
                'get_member': 'No direct replacement',
                'has_union': 'Use ida_typeinf.tinfo_t.has_union instead',
                'id': 'Use ida_typeinf.tinfo_t.get_tid instead',
                'is_choosable': 'No direct replacement',
                'is_copyof': 'No direct replacement',
                'is_frame': 'Use ida_typeinf.tinfo_t.is_frame instead',
                'is_ghost': 'No direct replacement',
                'is_hidden': 'No direct replacement',
                'is_mappedto': 'No direct replacement',
                'is_synced': 'No direct replacement',
                'is_union': 'Use ida_typeinf.tinfo_t.is_union instead',
                'is_varstr': 'Use ida_typeinf.tinfo_t.is_varstruct instead',
                'like_union': 'No direct replacement',
                'members': 'No direct replacement',
                'memqty': 'Use ida_typeinf.tinfo_t.get_udt_nmembers instead',
                'ordinal': 'Use ida_typeinf.tinfo_t.get_ordinal instead',
                'props': 'No direct replacement',
                'set_alignment': 'No direct replacement',
                'thisown': 'No direct replacement'
            },
            'struct_field_visitor_t': {
                'visit_field': 'No direct replacement'
            },
            'udm_visitor_t': {
                'visit_udm': 'No direct replacement'
            }
        }

        # Enum-related API changes
        self.enum_api_changes: Dict[str, str] = {
            # Direct replacements with idc module
            'add_enum': 'Use idc.add_enum instead',
            'add_enum_member': 'Use idc.add_enum_member instead',
            'del_enum': 'Use idc.del_enum instead',
            'del_enum_member': 'Use idc.del_enum_member instead',
            'get_bmask_cmt': 'Use idc.get_bmask_cmt instead',
            'get_bmask_name': 'Use idc.get_bmask_name instead',
            'get_enum': 'Use idc.get_enum instead',
            'get_enum_cmt': 'Use idc.get_enum_cmt instead',
            'get_enum_flag': 'Use idc.get_enum_flag instead',
            'get_enum_member': 'Use idc.get_enum_member instead',
            'get_enum_member_bmask': 'Use idc.get_enum_member_bmask instead',
            'get_enum_member_by_name': 'Use idc.get_enum_member_by_name instead',
            'get_enum_member_cmt': 'Use idc.get_enum_member_cmt instead',
            'get_enum_member_enum': 'Use idc.get_enum_member_enum instead',
            'get_enum_member_name': 'Use idc.get_enum_member_name instead',
            'get_enum_member_value': 'Use idc.get_enum_member_value instead',
            'get_enum_name': 'Use idc.get_enum_name instead',
            'get_enum_size': 'Use idc.get_enum_size instead',
            'get_enum_width': 'Use idc.get_enum_width instead',
            'get_first_bmask': 'Use idc.get_first_bmask instead',
            'get_first_enum_member': 'Use idc.get_first_enum_member instead',
            'get_last_bmask': 'Use idc.get_last_bmask instead',
            'get_last_enum_member': 'Use idc.get_last_enum_member instead',
            'get_next_bmask': 'Use idc.get_next_bmask instead',
            'get_next_enum_member': 'Use idc.get_next_enum_member instead',
            'get_prev_bmask': 'Use idc.get_prev_bmask instead',
            'get_prev_enum_member': 'Use idc.get_prev_enum_member instead',
            'is_bf': 'Use idc.is_bf instead',
            'set_bmask_cmt': 'Use idc.set_bmask_cmt instead',
            'set_bmask_name': 'Use idc.set_bmask_name instead',
            'set_enum_bf': 'Use idc.set_enum_bf instead',
            'set_enum_cmt': 'Use idc.set_enum_cmt instead',
            'set_enum_flag': 'Use idc.set_enum_flag instead',
            'set_enum_member_cmt': 'Use idc.set_enum_member_cmt instead',
            'set_enum_member_name': 'Use idc.set_enum_member_name instead',
            'set_enum_name': 'Use idc.set_enum_name instead',
            'set_enum_width': 'Use idc.set_enum_width instead',

            # Removed functions with no direct replacement
            'for_all_enum_members': 'Function removed in IDA 9.0',
            'get_enum_idx': 'Function removed in IDA 9.0',
            'get_enum_member_serial': 'Function removed in IDA 9.0',
            'get_enum_name2': 'Function removed in IDA 9.0',
            'get_enum_qty': 'Function removed in IDA 9.0',
            'get_enum_type_ordinal': 'Function removed in IDA 9.0',
            'get_first_serial_enum_member': 'Function removed in IDA 9.0',
            'get_last_serial_enum_member': 'Function removed in IDA 9.0',
            'get_next_serial_enum_member': 'Function removed in IDA 9.0',
            'get_prev_serial_enum_member': 'Function removed in IDA 9.0',
            'getn_enum': 'Function removed in IDA 9.0',
            'is_enum_fromtil': 'Function removed in IDA 9.0',
            'is_enum_hidden': 'Function removed in IDA 9.0',
            'is_ghost_enum': 'Function removed in IDA 9.0',
            'is_one_bit_mask': 'Function removed in IDA 9.0',
            'set_enum_fromtil': 'Function removed in IDA 9.0',
            'set_enum_ghost': 'Function removed in IDA 9.0',
            'set_enum_hidden': 'Function removed in IDA 9.0',
            'set_enum_idx': 'Function removed in IDA 9.0',
            'set_enum_type_ordinal': 'Function removed in IDA 9.0'
        }

        # Add enum visitor class method
        self.removed_class_members['enum_member_visitor_t'] = {
            'visit_enum_member': 'No direct replacement'
        }

        self.removed_funcs.update(self.enum_api_changes)
    
        # ida_typeinf removed functions
        self.typeinf_removed_funcs: Dict[str, str] = {
            'ida_typeinf.callregs_t_regcount': 'No direct replacement',
            'ida_typeinf.get_ordinal_from_idb_type': 'No direct replacement',
            'ida_typeinf.is_autosync': 'No direct replacement',
            'ida_typeinf.get_udm_tid': 'Use tinfo_t.get_udm_tid instead',
            'ida_typeinf.get_tinfo_tid': 'Use tinfo_t.get_tid instead',
            'ida_typeinf.tinfo_t_get_stock': 'No direct replacement',
            'ida_typeinf.get_ordinal_qty': 'Use ida_typeinf.get_ordinal_count or ida_typeinf.get_ordinal_limit instead',
            'ida_typeinf.import_type': 'Use idc.import_type instead'
        }

        # ida_frame removed functions
        self.frame_removed_funcs: Dict[str, str] = {
            'ida_frame.get_stkvar': 'Use tinfo_t methods instead',
            'ida_frame.get_frame': 'Use tinfo_t.get_func_frame instead',
            'ida_frame.get_frame_member_by_id': 'No direct replacement',
            'ida_frame.get_min_spd_ea': 'No direct replacement',
            'ida_frame.delete_unreferenced_stkvars': 'No direct replacement',
            'ida_frame.delete_wrong_stkvar_ops': 'No direct replacement'
        }

        # ida_bytes removed functions
        self.bytes_removed_funcs: Dict[str, str] = {
            'ida_bytes.free_chunck': 'No direct replacement',
            'ida_bytes.get_8bit': 'No direct replacement'
        }

        self.removed_methods.update({
            'enum_type_data_t.get_constant_group': 'No direct replacement'
        })

        self.modified_methods: Dict[str, Tuple[str, str]] = {
            'tinfo_t.find_udm': (
                'find_udm(self, udm: "udmt_t *", strmem_flags: "int") -> "int"',
                'find_udm(self, name: "char const *", strmem_flags: "int") -> "int"'
            ),
            'tinfo_t.get_type_by_edm_name': (
                'get_type_by_edm_name(self, mname: "const char *", til: "til_t"=None) -> "bool"',
                'get_edm_by_name(self, mname: "char const *", til: "til_t"=None) -> "ssize_t"'
            ),
            'ida_frame.define_stkvar': (
                'define_stkvar(pfn: "func_t *", name: "const char *", off: "sval_t", flags: "flags64_t", ti: "const opinfo_t *", nbytes: "asize_t") -> bool',
                'define_stkvar(pfn: "func_t *", name: "char const *", off: "sval_t", tif: "tinfo_t", repr: "value_repr_t"=None) -> "bool"'
            )
        }

        self.removed_funcs.update(self.typeinf_removed_funcs)
        self.removed_funcs.update(self.frame_removed_funcs)
        self.removed_funcs.update(self.bytes_removed_funcs)



        # ida_bytes
        self.modified_funcs.update({
            'ida_bytes.op_enum': (
                'op_enum(ea: "ea_t", n: "int", id: "enum_t", serial: "uchar"=0) -> "bool"',
                'op_enum(ea: "ea_t", n: "int", id: "tid_t", serial: "uchar"=0) -> "bool"'
            ),
            'ida_bytes.get_enum_id': (
                'get_enum_id(ea: "ea_t", n: "int") -> "tid_t"',
                'get_enum_id(ea: "ea_t", n: "int") -> "enum_t"'
            ),
            'ida_bytes.parse_binpat_str': (
                'parse_binpat_str(out: "compiled_binpat_vec_t", ea: "ea_t", _in: "char const *", radix: "int", strlits_encoding: "int"=0) -> "str"',
                'parse_binpat_str(out: "compiled_binpat_vec_t", ea: "ea_t", _in: "char const *", radix: "int", strlits_encoding: "int"=0) -> "bool"'
            ),
            'ida_bytes.bin_search3': (
                'bin_search3(start_ea: "ea_t", end_ea: "ea_t", data: "compiled_binpat_vec_t", flags: "int) -> ea_t',
                'bin_search(start_ea: "ea_t", end_ea: "ea_t", data: "compiled_binpat_vec_t const &", flags: "int") -> (ea_t, size_t)'
            ),
            'ida_bytes.get_octet2': (
                'get_octet2(ogen: "octet_generator_t") -> "uchar_t*"',
                'get_octet(ogen: "octet_generator_t") -> "uchar_t*"'
            )
        })

        # IDC removed functions
        self.removed_funcs.update({
            'idc.find_text': 'Use ida_bytes functions instead',
            'idc.find_binary': 'Use ida_bytes functions instead'
        })

        # ida_dirtree removed functions
        self.removed_funcs.update({
            'ida_dirtree.dirtree_cursor_root_cursor': 'No direct replacement',
            'ida_dirtree.dirtree_t_errstr': 'No direct replacement'
        })

        # ida_diskio removed functions
        self.removed_funcs.update({
            'ida_diskio.enumerate_files2': 'No direct replacement',
            'ida_diskio.eclose': 'No direct replacement'
        })

        # ida_graph changes
        self.moved_classes.update({
            'ida_graph.node_ordering_t': 'ida_gdl.node_ordering_t',
            'ida_graph.edge_t': 'ida_gdl.edge_t'
        })

        self.renamed_classes.update({
            'ida_graph.abstract_graph_t': 'drawable_graph_t',
            'ida_graph.mutable_graph_t': 'interactive_graph_t'
        })

        self.renamed_funcs.update({
            'ida_graph.create_mutable_graph': 'create_interactive_graph',
            'ida_graph.delete_mutable_graph': 'delete_interactive_graph',
            'ida_graph.grcode_create_mutable_graph': 'grcode_create_interactive_graph'
        })

        # ida_hexrays changes
        self.removed_funcs.update({
            'ida_hexrays.get_member_type': 'No direct replacement',
            'ida_hexrays.checkout_hexrays_license': 'No direct replacement',
            'ida_hexrays.cinsn_t_insn_is_epilog': 'No direct replacement'
        })

        # Modified method signatures for Hexrays classes
        self.modified_methods.update({
            'Hexrays_Hooks.flowchart': (
                'flowchart(self, fc: "qflow_chart_t") -> "int"',
                'flowchart(self, fc: "qflow_chart_t", mba: "mba_t") -> "int"'
            ),
            'valrng_t.cvt_to_cmp': (
                'cvt_to_cmp(self, strict: "bool") -> "bool"',
                'cvt_to_cmp(self) -> "bool"'
            ),
            'valrng_t.max_value': (
                'max_value(self, size_ : "int") -> "uvlr_t"',
                'max_value(self) -> "uvlr_t"'
            ),
            'valrng_t.min_svalue': (
                'min_svalue(self, size_: "int") -> "uvlr_t"',
                'min_svalue(self) -> "uvlr_t"'
            ),
            'valrng_t.max_svalue': (
                'max_svalue(self, size_: "int") -> "uvlr_t"',
                'max_svalue(self) -> "uvlr_t"'
            ),
            'stkvar_ref_t.get_stkvar': (
                'get_stkvar(self, p_off=None: "uval_t *") -> "member_t *"',
                'get_stkvar(self, udm: "udm_t"=None, p_off: "uval_t *"=None) -> "ssize_t"'
            ),
            'mop_t.get_stkvar': (
                'get_stkvar(self, p_off: "uval_t *") -> "member_t *"',
                'get_stkvar(self, udm: "udm_t"=None, p_off: "uval_t *"=None) -> "ssize_t"'
            ),
            'ida_hexrays.save_user_labels2': (
                'save_user_labels2(func_ea: "ea_t", user_labels: "user_labels_t", func: "cfunc_t"=None) -> "void"',
                'save_user_labels(func_ea: "ea_t", user_labels: "user_labels_t", func: "cfunc_t"=None) -> "void"'
            ),
            'ida_hexrays.restore_user_labels2': (
                'restore_user_labels2(func_ea: "ea_t", func: "cfunc_t"=None) -> "user_labels_t *"',
                'restore_user_labels(func_ea: "ea_t", func: "cfunc_t"=None) -> "user_labels_t *"'
            )
        })

        # Removed methods for vdui_t
        self.removed_methods.update({
            'vdui_t.set_strmem_type': 'No direct replacement',
            'vdui_t.rename_strmem': 'No direct replacement'
        })

        # ida_idaapi removed functions
        self.removed_funcs.update({
            'ida_idaapi.get_inf_structure': 'Use specific inf_get_* accessors instead',
            'ida_idaapi.loader_input_t_from_linput': 'No direct replacement',
            'ida_idaapi.loader_input_t_from_capsule': 'No direct replacement',
            'ida_idaapi.loader_input_t_from_fp': 'No direct replacement'
        })

        # ida_idp removed methods
        self.removed_methods.update({
            '_processor_t.has_realcvt': 'No direct replacement',
            'processor_t.get_uFlag': 'No direct replacement'
        })

        # ida_ieee removed methods
        self.removed_methods.update({
            'fpvalue_t._get_10bytes': 'No direct replacement',
            'fpvalue_t._set_10bytes': 'No direct replacement'
        })

        # ida_kernwin changes
        self.removed_funcs.update({
            'ida_kernwin.place_t_as_enumplace_t': 'No direct replacement',
            'ida_kernwin.place_t_as_structplace_t': 'No direct replacement',
            'ida_kernwin.open_enums_window': 'No direct replacement',
            'ida_kernwin.open_structs_window': 'No direct replacement',
            'ida_kernwin.choose_struc': 'No direct replacement',
            'ida_kernwin.choose_enum': 'No direct replacement',
            'ida_kernwin.choose_enum_by_value': 'No direct replacement'
        })

        # ida_kernwin removed classes
        self.removed_classes: Dict[str, str] = {
            'ida_kernwin.enumplace_t': 'No direct replacement',
            'ida_kernwin.structplace_t': 'No direct replacement'
        }

        # ida_kernwin removed methods
        self.removed_methods.update({
            'place_t.as_enumplace_t': 'No direct replacement',
            'place_t.as_structplace_t': 'No direct replacement',
            'twinpos_t.place_as_enumplace_t': 'No direct replacement',
            'twinpos_t.place_as_structplace_t': 'No direct replacement',
            'tagged_line_sections_t.find_in': 'No direct replacement'
        })

        # ida_kernwin function aliases
        self.function_aliases: Dict[str, str] = {
            'place_t_as_idaplace_t': 'place_t.as_idaplace_t',
            'place_t_as_simpleline_place_t': 'place_t.as_simpleline_place_t',
            'place_t_as_tiplace_t': 'place_t.as_tiplace_t',
            'bookmarks_t_mark': 'bookmarks_t.mark',
            'bookmarks_t_get_desc': 'bookmarks_t.get_desc',
            'bookmarks_t_find_index': 'bookmarks_t.find_index',
            'bookmarks_t_size': 'bookmarks_t.size',
            'bookmarks_t_erase': 'bookmarks_t.erase',
            'bookmarks_t_get_dirtree_id': 'bookmarks_t.get_dirtree_id',
            'bookmarks_t_get': 'bookmarks_t.get',
            'netnode.exist': 'netnode.exists'
        }

        # ida_lines removed functions
        self.removed_funcs.update({
            'ida_lines.set_user_defined_prefix': 'No direct replacement'
        })

        # ida_nalt removed functions
        self.removed_funcs.update({
            'ida_nalt.validate_idb_names': 'No direct replacement'
        })

        # ida_pro removed functions
        self.removed_funcs.update({
            'ida_pro.uchar_array_frompointer': 'Use new pointer classes',
            'ida_pro.tid_array_frompointer': 'Use new pointer classes',
            'ida_pro.ea_array_frompointer': 'Use new pointer classes',
            'ida_pro.sel_array_frompointer': 'Use new pointer classes',
            'ida_pro.int_pointer_frompointer': 'Use new pointer classes',
            'ida_pro.sel_pointer_frompointer': 'Use new pointer classes',
            'ida_pro.ea_pointer_frompointer': 'Use new pointer classes'
        })

        # ida_regfinder removed functions
        self.removed_funcs.update({
            'ida_regfinder.reg_value_info_t_make_dead_end': 'No direct replacement',
            'ida_regfinder.reg_value_info_t_make_aborted': 'No direct replacement',
            'ida_regfinder.reg_value_info_t_make_badinsn': 'No direct replacement',
            'ida_regfinder.reg_value_info_t_make_unkinsn': 'No direct replacement',
            'ida_regfinder.reg_value_info_t_make_unkfunc': 'No direct replacement',
            'ida_regfinder.reg_value_info_t_make_unkloop': 'No direct replacement',
            'ida_regfinder.reg_value_info_t_make_unkmult': 'No direct replacement',
            'ida_regfinder.reg_value_info_t_make_num': 'No direct replacement',
            'ida_regfinder.reg_value_info_t_make_initial_sp': 'No direct replacement'
        })

        # modified method signatures
        self.modified_methods.update({
            '_processor_t.gen_stkvar_def': (
                'gen_stkvar_def(ctx: "outctx_t &", mptr: "member_t const *", v: "sval_t") -> ssize_t',
                'gen_stkvar_def(ctx: "outctx_t &", mptr: "udm_t", v: "sval_t", tid: "tid_t") -> "ssize_t"'
            ),
            'IDP_Hooks.ev_gen_stkvar_def': (
                'ev_gen_stkvar_def(self, *args) -> "int"',
                'ev_gen_stkvar_def(self, outctx: "outctx_t *", stkvar: "udm_t", v: "sval_t", tid: "tid_t") -> "int"'
            ),
            'ida_regfinder.invalidate_regfinder_cache': (
                'invalidate_regfinder_cache(ea: "ea_t") -> "void"',
                'invalidate_regfinder_cache(from=BADADDR: "ea_t", to=BADADDR: "ea_t") -> "void"'
            )
        })

        # ida_registry removed functions
        self.removed_funcs.update({
            'ida_registry.reg_load': 'No direct replacement',
            'ida_registry.reg_flush': 'No direct replacement'
        })

        # ida_search removed functions
        self.removed_funcs.update({
            'ida_search.find_binary': 'No direct replacement'
        })

        # ida_ua changes
        self.removed_funcs.update({
            'ida_ua.construct_macro': 'Use macro_constructor_t.construct_macro instead'
        })

        self.modified_methods.update({
            'ida_ua.construct_macro2': (
                'construct_macro2(_this: "macro_constructor_t *", insn: "insn_t *", enable: "bool") -> "bool"',
                'construct_macro(_this: "macro_constructor_t *", insn: "insn_t *", enable: "bool") -> "bool"'
            )
        })

        # idautils modified functions
        self.modified_funcs.update({
            'idautils.Structs': (
                'Structs() -> [(idx, sid, name)]',
                'Structs() -> [(ordinal, sid, name)]'
            ),
            'idautils.StructMembers': (
                'StructMembers(sid) -> [(offset, name, size)]',
                'StructMembers(sid) -> [(offset_in_bytes, name, size_in_bytes)]'
            )
        })

        # IDB events changes
        self.idb_event_changes: Dict[str, str] = {
            'truc_created': 'Use local_types_changed instead',
            'deleting_struc': 'Event removed',
            'struc_deleted': 'Use local_types_changed instead',
            'changing_struc_align': 'Event removed',
            'struc_align_changed': 'Use local_types_changed instead',
            'renaming_struc': 'Event removed',
            'struc_renamed': 'Use local_types_changed instead',
            'expanding_struc': 'Event removed',
            'struc_expanded': 'Use lt_udt_expanded, frame_expanded, local_types_changed instead',
            'struc_member_created': 'Use lt_udm_created, frame_udm_created, local_types_changed instead',
            'deleting_struc_member': 'Event removed',
            'struc_member_deleted': 'Use lt_udm_deleted, frame_udm_deleted, local_types_changed instead',
            'renaming_struc_member': 'Event removed',
            'struc_member_renamed': 'Use lt_udm_renamed, frame_udm_renamed, local_types_changed instead',
            'changing_struc_member': 'Event removed',
            'struc_member_changed': 'Use lt_udm_changed, frame_udm_changed, local_types_changed instead',
            'changing_struc_cmt': 'Event removed',
            'struc_cmt_changed': 'Use local_types_changed instead',
            'enum_created': 'Use local_types_changed instead',
            'deleting_enum': 'Event removed',
            'enum_deleted': 'Use local_types_changed instead',
            'renaming_enum': 'Event removed',
            'enum_renamed': 'Use local_types_changed instead',
            'changing_enum_bf': 'Use local_types_changed instead',
            'enum_bf_changed': 'Use local_types_changed instead',
            'changing_enum_cmt': 'Event removed',
            'enum_cmt_changed': 'Use local_types_changed instead',
            'enum_member_created': 'Use local_types_changed instead',
            'deleting_enum_member': 'Event removed',
            'enum_member_deleted': 'Use local_types_changed instead',
            'enum_width_changed': 'Use local_types_changed instead',
            'enum_flag_changed': 'Use local_types_changed instead',
            'enum_ordinal_changed': 'Event removed'
        }

    def _check_idb_event(self, node: ast.AST, warnings: List[str]):
        """Check for deprecated or removed IDB events"""
        if isinstance(node, ast.Name) and node.id in self.idb_event_changes:
            warnings.append(f"Line {node.lineno}: IDB event '{node.id}' has changed in IDA 9.0. {self.idb_event_changes[node.id]}")
        elif isinstance(node, ast.Attribute) and node.attr in self.idb_event_changes:
            warnings.append(f"Line {node.lineno}: IDB event '{node.attr}' has changed in IDA 9.0. {self.idb_event_changes[node.attr]}")




    def _check_function_alias(self, node: ast.Call, warnings: List[str]):
        """Check for function aliases that should be updated"""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.function_aliases:
                warnings.append(f"Line {node.lineno}: Function '{func_name}' should be replaced with '{self.function_aliases[func_name]}'")


    def _check_method_signature(self, node: ast.Call, warnings: List[str]):
        """Check for modified method signatures"""
        if isinstance(node.func, ast.Attribute):
            method_name = f"{self._get_full_name(node.func.value)}.{node.func.attr}"
            if method_name in self.modified_methods:
                old_sig, new_sig = self.modified_methods[method_name]
                warnings.append(f"Line {node.lineno}: Method signature changed for '{method_name}'\nOld: {old_sig}\nNew: {new_sig}")


    def _check_attribute_access(self, node: ast.Attribute, warnings: List[str]):
        """Check for usage of removed class members and methods"""
        if isinstance(node.value, ast.Name):
            class_name = node.value.id
            if class_name in self.removed_class_members:
                attr_name = node.attr
                if attr_name in self.removed_class_members[class_name]:
                    replacement = self.removed_class_members[class_name][attr_name]
                    warnings.append(f"Line {node.lineno}: Attribute/Method '{class_name}.{attr_name}' was removed in IDA 9.0. {replacement}")


    def check_file(self, filepath: str) -> List[str]:
        """Check a Python file for IDA API compatibility issues"""
        warnings = []
        
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # check function calls
                if isinstance(node, ast.Call):
                    self._check_function_alias(node, warnings)
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = f"{self._get_full_name(node.func)}"
                    else:
                        continue

                    self._check_function_usage(node, func_name, warnings)

                # check class usage
                elif isinstance(node, (ast.Name, ast.Attribute)):
                    class_name = self._get_full_name(node) if isinstance(node, ast.Attribute) else node.id
                    self._check_class_usage(node, class_name, warnings)

                # check method calls
                elif isinstance(node, ast.Attribute):
                    method_name = f"{self._get_full_name(node.value)}.{node.attr}"
                    self._check_method_usage(node, method_name, warnings)

                # analyze imports
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ["ida_struct", "ida_enum"]:
                            warnings.append(f"Line {node.lineno}: Importing {alias.name} is not supported in IDA 9.0, modules were removed")

                if isinstance(node, ast.Attribute):
                    self._check_attribute_access(node, warnings)
                
                self._check_idb_event(node, warnings)


        except Exception as e:
            warnings.append(f"Error analyzing {filepath}: {str(e)}")
            
        return warnings

    def _check_function_usage(self, node: ast.AST, func_name: str, warnings: List[str]):
        """Check function usage for removals, modifications and renames"""
        if func_name in self.removed_funcs:
            warnings.append(f"Line {node.lineno}: Function '{func_name}' was removed in IDA 9.0. {self.removed_funcs[func_name]}")
        
        if func_name in self.modified_funcs:
            old_sig, new_sig = self.modified_funcs[func_name]
            warnings.append(f"Line {node.lineno}: Function '{func_name}' signature changed in IDA 9.0\nOld: {old_sig}\nNew: {new_sig}")
        
        if func_name in self.renamed_funcs:
            warnings.append(f"Line {node.lineno}: Function '{func_name}' was renamed to '{self.renamed_funcs[func_name]}' in IDA 9.0")

    def _check_class_usage(self, node: ast.AST, class_name: str, warnings: List[str]):
        """Check class usage for moves and renames"""
        if class_name in self.moved_classes:
            warnings.append(f"Line {node.lineno}: Class '{class_name}' was moved to '{self.moved_classes[class_name]}' in IDA 9.0")
        
        if class_name in self.renamed_classes:
            warnings.append(f"Line {node.lineno}: Class '{class_name}' was renamed to '{self.renamed_classes[class_name]}' in IDA 9.0")

    def _check_method_usage(self, node: ast.AST, method_name: str, warnings: List[str]):
        """Check method usage for removals"""
        if method_name in self.removed_methods:
            warnings.append(f"Line {node.lineno}: Method '{method_name}' was removed in IDA 9.0. {self.removed_methods[method_name]}")

    def _get_full_name(self, node: ast.AST) -> str:
        """Get the full dotted name of an attribute node"""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return '.'.join(reversed(parts))

def main():
    """migration checker"""
    checker = IdaPythonMigrationChecker()
    path = sys.argv[1] if len(sys.argv) > 1 else '.'

    # Get all .py files in current directory recursively
    py_files = Path(path).rglob('*.py')
    
    for py_file in py_files:
        if "venv" in str(py_file):
            continue
        if "site-packages" in str(py_file):
            continue
        #print(f"\nChecking {py_file}...")
        warnings = checker.check_file(str(py_file))
        if warnings:
            print(f"\nWarnings for {py_file}:")
            for warning in warnings:
                print(warning)

if __name__ == '__main__':
    main()