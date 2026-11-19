"""Validate QoS node separation only when both cluster kinds are present."""
OLD = ('\tif (pset_node_is_empty(low_node) || pset_node_is_empty(high_node)) {\n'
       '\t\tlow_node = high_node = sched_boot_pset_node;\n'
       '\t}\n'
       '\tassert3p(low_node, !=, PSET_NODE_NULL);\n'
       '\tassert3p(high_node, !=, PSET_NODE_NULL);\n'
       '\tif (sched_is_standard_topology()) {\n'
       '\t\tassert3p(low_node, !=, high_node);\n'
       '\t}')
NEW = ('\t/* A single-cluster boot deliberately uses the boot node for both roles. */\n'
       '\tbool boot_node_fallback = pset_node_is_empty(low_node) || pset_node_is_empty(high_node);\n'
       '\tif (boot_node_fallback) {\n'
       '\t\tlow_node = high_node = sched_boot_pset_node;\n'
       '\t}\n'
       '\tassert3p(low_node, !=, PSET_NODE_NULL);\n'
       '\tassert3p(high_node, !=, PSET_NODE_NULL);\n'
       '\tif (sched_is_standard_topology() && !boot_node_fallback) {\n'
       '\t\tassert3p(low_node, !=, high_node);\n'
       '\t}')


def adapt_source(text):
    if text.count(OLD) != 1:
        raise ValueError('Unexpected scheduler fallback; do not remove general topology assertions')
    return text.replace(OLD, NEW, 1)
