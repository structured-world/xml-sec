//! The caller's libxml2 functions the library calls, under their libxml2
//! names. `xml-sec-libxml2` resolves them in the running process; the library
//! links no libxml2 of its own.

pub(crate) use xml_sec_libxml2::ffi::libxml2::{
    xml_free_doc as xmlFreeDoc, xml_get_id as xmlGetID, xml_get_prop as xmlGetProp,
    xml_node_add_content as xmlNodeAddContent, xml_node_get_content as xmlNodeGetContent,
    xml_output_buffer_write_string as xmlOutputBufferWriteString, xml_search_ns as xmlSearchNs,
    xml_str_equal as xmlStrEqual, xml_xpath_cmp_nodes as xmlXPathCmpNodes,
    xml_xpath_free_node_set as xmlXPathFreeNodeSet, xml_xpath_node_set_add as xmlXPathNodeSetAdd,
    xml_xpath_node_set_add_ns as xmlXPathNodeSetAddNs,
    xml_xpath_node_set_contains as xmlXPathNodeSetContains,
    xml_xpath_node_set_create as xmlXPathNodeSetCreate,
};

/// Whether a supported libxml2 is loaded in the process; a function that
/// would read a tree fails otherwise.
pub(crate) fn readable() -> bool {
    xml_sec_libxml2::ffi::libxml2::available()
}
