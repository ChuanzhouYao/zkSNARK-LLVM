set(INPUTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/inputs)

#generate assignment table and circuit
#function(assign_ir)
#    list(POP_FRONT ARGV target)
#    list(POP_FRONT ARGV binary_name)
#    list(POP_FRONT ARGV input)
#    list(POP_FRONT ARGV private_input)
#    list(POP_FRONT ARGV curve_type)
#    list(POP_FRONT ARGV arithmetization)
#    if(NOT arithmetization STREQUAL "none")
#        set(witness_cols ${arithmetization})
#        list(POP_FRONT ARGV public_input_cols)
#        list(POP_FRONT ARGV component_constant_cols)
#        list(POP_FRONT ARGV lookup_constant_cols)
#        list(POP_FRONT ARGV component_selector_cols)
#        list(POP_FRONT ARGV lookup_selector_cols)
#        set(arithmetization_flag --column-sizes)
#        set(arithmetization_amount ${witness_cols} ${public_input_cols} ${component_constant_cols} ${lookup_constant_cols} ${component_selector_cols} ${lookup_selector_cols})
#    endif()
#    list(POP_FRONT ARGV max_num_provers_amount)
#
#    if(NOT max_num_provers_amount EQUAL 0)
#        set(max_num_provers_flag --max-num-provers)
#        set(max_num_provers_amount ${max_num_provers_amount})
#    endif()
#
#    if(NOT private_input STREQUAL "none")
#        set(minus_p -p)
#        set(private_input_string ${INPUTS_DIR}/${private_input})
#    endif()
#
#    add_custom_target(${target}_generate_crct
#            COMMAND $<TARGET_FILE:assigner>
#            -b ${binary_name}
#            -c circuit_${target}.crct
#            -e ${curve_type}
#            --generate-type circuit
#            ${max_num_provers_flag} ${max_num_provers_amount}
#            ${arithmetization_flag} ${arithmetization_amount}
#            DEPENDS ${target} $<TARGET_FILE:assigner>
#            COMMAND_EXPAND_LISTS
#            VERBATIM)
#
#    add_custom_target(${target}_generate_both
#        COMMAND $<TARGET_FILE:assigner>
#            -b ${binary_name}
#            -i ${INPUTS_DIR}/${input}
#            ${minus_p} ${private_input_string}
#            -c circuit_${target}.crct
#            -t assignment_${target}.tbl -e ${curve_type} --check
#            --generate-type circuit-assignment
#            ${max_num_provers_flag} ${max_num_provers_amount}
#            ${arithmetization_flag} ${arithmetization_amount}
#        DEPENDS ${target} ${INPUTS_DIR}/${input} $<TARGET_FILE:assigner>
#        COMMAND_EXPAND_LISTS
#        VERBATIM)
#
#    add_custom_target(${target}_generate_tbl
#        COMMAND $<TARGET_FILE:assigner>
#            -b ${binary_name}
#            -i ${INPUTS_DIR}/${input}
#            ${minus_p} ${private_input_string}
#            -t assignment_${target}.tbl -e ${curve_type} --check
#            --generate-type assignment
#            ${max_num_provers_flag} ${max_num_provers_amount}
#            ${arithmetization_flag} ${arithmetization_amount}
#        DEPENDS ${target} ${INPUTS_DIR}/${input} $<TARGET_FILE:assigner>
#        COMMAND_EXPAND_LISTS
#        VERBATIM)
#
#    add_custom_target(${target}_estimate_size
#        COMMAND $<TARGET_FILE:assigner>
#            -b ${binary_name}
#            -e ${curve_type}
#            --generate-type size_estimation
#            ${max_num_provers_flag} ${max_num_provers_amount}
#            ${arithmetization_flag} ${arithmetization_amount}
#        DEPENDS ${target} $<TARGET_FILE:assigner>
#        COMMAND_EXPAND_LISTS
#        VERBATIM)
#
#    add_custom_target(${target}_prepare_input
#        COMMAND $<TARGET_FILE:assigner>
#            -b ${binary_name}
#            -i ${INPUTS_DIR}/${input}
#            --generate-type public-input-column
#            --input-column ${target}_input_column.inp
#            -e ${curve_type}
#            ${arithmetization_flag} ${arithmetization_amount}
#        DEPENDS ${target} ${INPUTS_DIR}/${input}
#        COMMAND_EXPAND_LISTS
#        VERBATIM)
#endfunction()
#
#function(gen_proof target curve_type provers_amount)
#
#    if(provers_amount EQUAL 0)
#        gen_single_proof(${target} ${curve_type} 0)
#    else()
#        add_custom_target(${target}_prove)
#
#        foreach(prover_num RANGE 1 ${provers_amount})
#            math(EXPR prover_num_minus_1 "${prover_num} - 1")
#            gen_single_proof(${target} ${curve_type} ${prover_num})
#            add_dependencies(${target}_prove ${target}_prove${prover_num_minus_1})
#        endforeach()
#
#        add_custom_target(${target}_copy_input_for_proof
#            COMMAND ${CMAKE_COMMAND} -E make_directory transpiler_output_${target}
#            COMMAND ${CMAKE_COMMAND} -E copy ${target}_input_column.inp transpiler_output_${target}/public_input.inp
#            DEPENDS ${target}_prepare_input)
#
#        add_dependencies(${target}_prove ${target}_copy_input_for_proof)
#
#    endif()
#endfunction()
#
#function(gen_single_proof target curve_type provers_amount)
#
#    if(NOT provers_amount EQUAL 0)
#        set(multi_prover_flag --multi-prover)
#        math(EXPR prover_num "${provers_amount} - 1")
#    else()
#        set(prover_num "")
#    endif()
#
#    add_custom_target(${target}_prove${prover_num}
#        COMMAND $<TARGET_FILE:transpiler> -m gen-test-proof
#            -c circuit_${target}.crct${prover_num}
#            -t assignment_${target}.tbl${prover_num}
#            -o transpiler_output_${target}${prover_num}
#            -e ${curve_type}
#            ${multi_prover_flag}
#            DEPENDS ${target}_generate_crct ${target}_generate_tbl $<TARGET_FILE:transpiler>
#        COMMAND_EXPAND_LISTS
#        VERBATIM)
#endfunction()
#
#function(gen_evm_verifier target curve_type provers_amount)
#
#    if(provers_amount EQUAL 0)
#    gen_single_evm_verifier(${target} ${curve_type} 0)
#    else()
#        add_custom_target(${target}_evm_verifier)
#
#        foreach(prover_num RANGE 1 ${provers_amount})
#            math(EXPR prover_num_minus_1 "${prover_num} - 1")
#            gen_single_evm_verifier(${target} ${curve_type} ${prover_num})
#            add_dependencies(${target}_evm_verifier ${target}_evm_verifier${prover_num_minus_1})
#        endforeach()
#
#    endif()
#
#    add_custom_target(${target}_copy_input_for_evm_verifier
#            COMMAND ${CMAKE_COMMAND} -E make_directory transpiler_output_${target}
#            COMMAND ${CMAKE_COMMAND} -E copy ${target}_input_column.inp transpiler_output_${target}/public_input.inp
#            DEPENDS ${target}_prepare_input)
#    add_dependencies(${target}_evm_verifier ${target}_copy_input_for_evm_verifier)
#endfunction()
#
#function(gen_single_evm_verifier target curve_type provers_amount)
#
#    if(NOT provers_amount EQUAL 0)
#        set(multi_prover_flag --multi-prover)
#        math(EXPR prover_num "${provers_amount} - 1")
#    else()
#        set(prover_num "")
#    endif()
#
#    add_custom_target(${target}_evm_verifier${prover_num}
#        COMMAND $<TARGET_FILE:transpiler> -m gen-evm-verifier
#            -c circuit_${target}.crct${prover_num}
#            -t assignment_${target}.tbl${prover_num}
#            -o transpiler_output_${target}${prover_num}
#            -e ${curve_type}
#            ${multi_prover_flag}
#            --optimize-gates
#        DEPENDS ${target}_assign ${target}_prove${prover_num} $<TARGET_FILE:transpiler>
#        COMMAND_EXPAND_LISTS
#        VERBATIM)
#endfunction()

add_subdirectory(cpp)
#add_subdirectory(rust)
