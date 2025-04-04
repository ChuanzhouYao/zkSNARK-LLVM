/*
 * run_ppzksnark.cpp
 *
 *      Author: Ahmed Kosba
 */

#include "CircuitReader.hpp"
#include "json.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <gmpxx.h>

using json = nlohmann::json;
std::string FieldTtoString(FieldT cc){
    mpz_t t;
    mpz_init(t);
    cc.as_bigint().to_mpz(t);
    mpz_class big_coeff(t);
    return big_coeff.get_str();
}

json Inputs2Json(const r1cs_primary_input<FieldT> &primary_input, const r1cs_auxiliary_input<FieldT> &auxiliary_input){
    json  j_inputs, j_witness;

    for(FieldT const & iter:primary_input){
        j_inputs.push_back(FieldTtoString(iter));
    }
    for(FieldT const & iter:auxiliary_input){
        j_witness.push_back(FieldTtoString(iter));
    }

    std::cout<<"inputtest1\n";

    json jValue;
    jValue["inputs"] = j_inputs;
    jValue["witness"] = j_witness;

    return jValue;
}

json LinearCombinationJson(linear_combination<FieldT> vec){
    json jc;
    json jlt;

    for(linear_term<FieldT> const & lt:vec){
        json jt;
        jlt.push_back(lt.index);
        jlt.push_back(FieldTtoString(lt.coeff));

        jc.push_back(jlt);
    }

    return jc;
}
void ToR1CSJson(r1cs_constraint_system<FieldT> &in_cs, const std::string &out_fname){
    json r1cs_header;
    r1cs_header["instance_number"] = in_cs.primary_input_size;
    r1cs_header["witness_number"] = in_cs.auxiliary_input_size;
    r1cs_header["constraint_number"] = in_cs.num_constraints();

    std::ofstream out(out_fname);
    if(out.is_open()){
        json j;
        j["r1cs"] = r1cs_header;
        out << j << "\n";

        for(r1cs_constraint<FieldT> & constraint : in_cs.constraints){
            json jconstraints;
            jconstraints["A"] = LinearCombinationJson(constraint.a);
            jconstraints["B"] = LinearCombinationJson(constraint.b);
            jconstraints["C"] = LinearCombinationJson(constraint.c);

            out << jconstraints << "\n";
        }
        out.close();
    }else{
        std::cout << "R1CS output file can`t open\n";
    }

}
void ToR1CSinputJson(const std::string &R1CSinName, const json & jsonAssignments){
    std::ofstream out(R1CSinName+".in");
    if(out.is_open()){
        out << jsonAssignments;
        out.close();
    }else{
        std::cout << "R1CS Assignments output file can`t open\n";
    }

}
int main(int argc, char **argv) {

	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
    json assignments;
	int inputStartIndex = 0;

	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(
			*pb);
	const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	// extract primary and auxiliary input
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());

    std::cout<< "test1\n";
    assignments = Inputs2Json(primary_input, auxiliary_input);
    
    std::cout<< "test2\n";
	// only print the circuit output values if both flags MONTGOMERY and BINARY outputs are off (see CMakeLists file)
	// In the default case, these flags should be ON for faster performance.
	ToR1CSJson(cs, argv[3]);
   std::cout<< "test3\n";
    ToR1CSinputJson(argv[3], assignments);

	return 0;
}

