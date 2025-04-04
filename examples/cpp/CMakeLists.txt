add_custom_target(compile_cpp_examples)
add_custom_target(cpp_examples_generate_tbl)
add_custom_target(cpp_examples_generate_crct)
add_custom_target(cpp_examples_generate_both)
add_custom_target(prove_cpp_examples)
add_custom_target(cpp_examples_estimate_size)

function(add_example_without_proving example_target)
    set(prefix ARG)
    set(noValues "")
    set(singleValues INPUT PRIVATE_INPUT CURVE_TYPE MAX_NUM_PROVERS)
    set(multiValues SOURCES COMPILER_OPTIONS ARITHMETIZARION)
    cmake_parse_arguments(${prefix}
                        "${noValues}"
                        "${singleValues}"
                        "${multiValues}"
                        ${ARGN})

    add_circuit(${example_target}
                SOURCES ${ARG_SOURCES}
                COMPILER_OPTIONS ${ARG_COMPILER_OPTIONS}

                LINK_LIBRARIES
                crypto3::algebra
                crypto3::block
                crypto3::blueprint
                crypto3::codec
                crypto3::containers
                crypto3::hash
                crypto3::kdf
                crypto3::mac
                marshalling::core
                marshalling::crypto3_algebra
                marshalling::crypto3_multiprecision
                marshalling::crypto3_zk
                crypto3::math
                crypto3::modes
                crypto3::multiprecision
                crypto3::passhash
                crypto3::pbkdf
                crypto3::threshold
                crypto3::pkpad
                crypto3::pubkey
                crypto3::random
                crypto3::stream
                crypto3::vdf
                crypto3::zk

                ${Boost_LIBRARIES})

    set(binary_name ${example_target}.ll)

    add_dependencies(compile_cpp_examples ${example_target})

    if(NOT DEFINED ARG_PRIVATE_INPUT)
        set(ARG_PRIVATE_INPUT "none")
    endif()

    if(NOT DEFINED ARG_MAX_NUM_PROVERS)
        set(ARG_MAX_NUM_PROVERS 0)
    endif()

    if(NOT DEFINED ARG_ARITHMETIZARION)
        set(ARG_ARITHMETIZARION "none")
    endif()

#    assign_ir(${example_target} ${binary_name} ${ARG_INPUT} ${ARG_PRIVATE_INPUT} ${ARG_CURVE_TYPE} ${ARG_ARITHMETIZARION} ${ARG_MAX_NUM_PROVERS})

#    add_dependencies(cpp_examples_generate_tbl ${example_target}_generate_tbl)
#    add_dependencies(cpp_examples_generate_crct ${example_target}_generate_crct)
#    add_dependencies(cpp_examples_generate_both ${example_target}_generate_both)
#    add_dependencies(cpp_examples_estimate_size ${example_target}_estimate_size)
endfunction()

function(add_example_with_proving example_target)
    set(prefix ARG)
    set(noValues "")
    set(singleValues INPUT PRIVATE_INPUT CURVE_TYPE MAX_NUM_PROVERS)
    set(multiValues SOURCES)
    cmake_parse_arguments(${prefix}
                        "${noValues}"
                        "${singleValues}"
                        "${multiValues}"
                        ${ARGN})

    add_example_without_proving(${example_target} ${ARGN})

    if(NOT DEFINED ARG_MAX_NUM_PROVERS)
        set(ARG_MAX_NUM_PROVERS 0)
    endif()

#    gen_proof(${example_target} ${ARG_CURVE_TYPE} ${ARG_MAX_NUM_PROVERS})
#    add_dependencies(prove_cpp_examples ${example_target}_prove)

    if(GENERATE_EVM_VERIFIER)
        gen_evm_verifier(${example_target} ${ARG_CURVE_TYPE} ${ARG_MAX_NUM_PROVERS})
        add_dependencies(prove_cpp_examples ${example_target}_evm_verifier)
    endif()

endfunction()
#
#------------ new
#---add
add_example_without_proving(add SOURCES add.cpp INPUT add.inp CURVE_TYPE pallas)

add_example_without_proving(add1 SOURCES add1.cpp INPUT add1.inp CURVE_TYPE pallas)
add_example_without_proving(add10 SOURCES add10.cpp INPUT add10.inp CURVE_TYPE pallas)
add_example_without_proving(add100 SOURCES add100.cpp INPUT add100.inp CURVE_TYPE pallas)
add_example_without_proving(add1000 SOURCES add1000.cpp INPUT add1000.inp CURVE_TYPE pallas)
#---mul
add_example_without_proving(mul1 SOURCES mul1.cpp INPUT mul1.inp CURVE_TYPE pallas)
add_example_without_proving(mul10 SOURCES mul10.cpp INPUT mul10.inp CURVE_TYPE pallas)
add_example_without_proving(mul100 SOURCES mul100.cpp INPUT mul100.inp CURVE_TYPE pallas)
add_example_without_proving(mul1000 SOURCES mul1000.cpp INPUT mul1000.inp CURVE_TYPE pallas)

#---------------------
add_example_without_proving(div1 SOURCES div1.cpp INPUT div1.inp CURVE_TYPE pallas)

add_example_without_proving(SHA256 SOURCES SHA256.cpp INPUT SHA256.inp CURVE_TYPE pallas)

add_example_without_proving(xor1 SOURCES xor1.cpp INPUT xor1.inp CURVE_TYPE pallas)

add_example_without_proving(not1 SOURCES not1.cpp INPUT not1.inp CURVE_TYPE pallas)

add_example_without_proving(left SOURCES left.cpp INPUT left.inp CURVE_TYPE pallas)
add_example_without_proving(right SOURCES right.cpp INPUT right.inp CURVE_TYPE pallas)

add_example_without_proving(readtest SOURCES readtest.cpp INPUT readtest.inp CURVE_TYPE pallas)

add_example_without_proving(neq SOURCES neq.cpp INPUT neq.inp CURVE_TYPE pallas)

add_example_without_proving(eq SOURCES eq.cpp INPUT eq.inp CURVE_TYPE pallas)

add_example_without_proving(integer SOURCES integer.cpp INPUT integer.inp CURVE_TYPE pallas)

add_example_without_proving(fortest SOURCES fortest.cpp INPUT fortest.inp CURVE_TYPE pallas)

add_example_without_proving(newtest SOURCES newtest.cpp INPUT newtest.inp CURVE_TYPE pallas)



add_example_without_proving(test1 SOURCES test1.cpp INPUT test1.inp CURVE_TYPE pallas)

add_example_without_proving(calltest SOURCES calltest.cpp INPUT calltest.inp CURVE_TYPE pallas)

add_example_without_proving(ramtest SOURCES ramtest.cpp INPUT ramtest.inp CURVE_TYPE pallas)

add_example_without_proving(sortverify SOURCES sortverify.cpp INPUT sortverify.inp CURVE_TYPE pallas)

add_example_without_proving(sort SOURCES sort.cpp INPUT sort.inp CURVE_TYPE pallas)


add_example_without_proving(AES128 SOURCES AES128.cpp INPUT AES128.inp CURVE_TYPE pallas)


#-----------

#add_example_without_proving(placeholder_verifier_cpp_example SOURCES placeholder_verifier.cpp INPUT placeholder_verifier.inp CURVE_TYPE pallas)
#add_example_with_proving(arithmetics_cpp_example SOURCES arithmetics.cpp INPUT arithmetics.inp CURVE_TYPE pallas)
#add_example_with_proving(integer_arithmetics_cpp_example SOURCES integer_arithmetics.cpp INPUT integer_arithmetics.inp CURVE_TYPE pallas)


