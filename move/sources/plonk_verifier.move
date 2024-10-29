module plonk_verifier_addr::plonk_verifier_core {
    use std::vector;
    use std::hash::{ sha2_256 };
    use plonk_verifier_addr::utilities_core::{append_value, bytes_to_uint256, powSmall, u256_to_fr, fr_to_u256, u256_to_bytes, new_g1, new_g2, point_acc_mul, prepare_pairing_g1_input, fr_acc_mul, get_coordinates, unset_first_bit};
    use std::bn254_algebra::{FormatFrMsb, Fr, G1, G2, Gt};
    use std::vector::{length, push_back, trim, reverse, pop_back};
    use aptos_std::crypto_algebra::{add, deserialize, Element, mul, one, zero, multi_pairing, eq, scalar_mul};
    #[test_only]
    use aptos_std::crypto_algebra::serialize;

    // BN254 curve constants
    const R_MOD: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    const R_MOD_MINUS_ONE: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
    const P_MOD: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // Aztec SRS constants
    const G2_SRS_0_X_0: u256 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2;
    const G2_SRS_0_X_1: u256 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed;
    const G2_SRS_0_Y_0: u256 = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b;
    const G2_SRS_0_Y_1: u256 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa;
    const G2_SRS_1_X_0: u256 = 0x22f1acbb03c4508760c2430af35865e7cdf9f3eb1224504fdcc3708ddb954a48;
    const G2_SRS_1_X_1: u256 = 0x2a344fad01c2ed0ed73142ae1752429eaea515c6f3f6b941103cc21c2308e1cb;
    const G2_SRS_1_Y_0: u256 = 0x159f15b842ba9c8449aa3268f981010d4c7142e5193473d80b464e964845c3f8;
    const G2_SRS_1_Y_1: u256 = 0x0efd30ac7b6f8d0d3ccbc2207587c2acbad1532dc0293f0d034cf8258cd428b3;
    const G1_SRS_X: u256 = 0x1fa4be93b5e7f7e674d5059b63554fab99638b304ed8310e9fa44c281ac9b03b;
    const G1_SRS_Y: u256 = 0x1a01ae7fac6228e39d3cb5a5e71fd31160f3241e79a5f48ffb3737e6c389b721;

    // Plonk verifier key constants
    const VK_NB_PUBLIC_INPUTS: u64 = 2;
    const VK_DOMAIN_SIZE: u256 = 67108864;
    const VK_INV_DOMAIN_SIZE: u256 = 0x30644e66c81e03716be83b486d6feabcc7ddd0fe6cbf5e72d585d142f7829b05;
    const VK_OMEGA: u256 = 0x1067569af1ff73b20113eff9b8d89d4a605b52b63d68f9ae1c79bd572f4e9212;
    const VK_QL_COM_X: u256 = 0x0fa5a168a474c4a774604f653710d47f487c70ea3fe67a5505f145b52ba5ae61;
    const VK_QL_COM_Y: u256 = 0x09d5fc411f9a6468c86ac309c7bcfc178d08792f35bea77b60f6afe5cec1856f;
    const VK_QR_COM_X: u256 = 0x2e30310821132e573f1dbcebf06be4bc7bfd7d82453a70fad26a696c9d8e7436;
    const VK_QR_COM_Y: u256 = 0x08082e65bee7b2f84f5770edc714f0fdce02449dd2c54e413c206a6f45ad4efb;
    const VK_QM_COM_X: u256 = 0x255da959bdc41020c115bc0a2c3fc359e108a5c3d0727a140d2b253cbe38ea69;
    const VK_QM_COM_Y: u256 = 0x030e212c5fd727579660fb90fca01867b1ae0b8fc3cea394e689faf9da6abaf6;
    const VK_QO_COM_X: u256 = 0x137e008127bd7922be14abcaa96bf8bd0ce8aa2079e87321fbef0e642362287f;
    const VK_QO_COM_Y: u256 = 0x2858706ad2afe31c036eea00663403028e0bab5aa3f5345ed5e0d1b1a665795a;
    const VK_QK_COM_X: u256 = 0x0293743461237504ce77d4271c7a3196e1bcf82cb8ee756a2b3e071834f893b5;
    const VK_QK_COM_Y: u256 = 0x22268ce90c81411487ede8994e30f96627e69b08d15c9bfc7adef9ed0c042070;
    const VK_S1_COM_X: u256 = 0x21f6f19b278b3d33b0532042b54a0a7a93a7ac7c75b082a0db3941d620e42f66;
    const VK_S1_COM_Y: u256 = 0x2079320b260e6260d67143f8d9ffacf869062921dd4b82f98da1f663ef43a7f9;
    const VK_S2_COM_X: u256 = 0x050f79d7cbada78913643b8f8f513528ed6cc7361dd464ea7983dfaab68a30d2;
    const VK_S2_COM_Y: u256 = 0x135b4c5d9a340ff993a8c2f27d191521b69b299960302fc51d1995151c4dde0e;
    const VK_S3_COM_X: u256 = 0x027bd831dedbfbcd07849426a421de0b9df8e5fe0dd0dc442ae7a74d06e3353f;
    const VK_S3_COM_Y: u256 = 0x26a8af654c2b2dde815be0693d48269debe0b710d6efd51b2d90c03e3b14eaab;
    const VK_COSET_SHIFT: u256 = 5;

    const VK_QCP_0_X: u256 = 0x033a8ad74d5e83d787976ec3fe5f370677ec444ee8ca76c5795b12fcfe45c591;
    const VK_QCP_0_Y: u256 = 0x170a6e08df69c3ada6484ba0fd637524e453dc505493e978a2b9eb100e499a00;
    const VK_INDEX_COMMIT_API_0: u256 = 31898231;

    const VK_NB_CUSTOM_GATES: u64 = 1;

    // Utils for Fiat Shamir
    const FS_ALPHA: u256 = 0x616C706861;
    const FS_BETA: u256 = 0x62657461;
    const FS_GAMMA: u256 = 0x67616d6d61;
    const FS_ZETA: u256 = 0x7a657461;
    const FS_GAMMA_KZG: u256 = 0x67616d6d61;

    // Utils for hash_fr
    const HASH_FR_BB: u256 = 0x0000000000000000000000000000000100000000000000000000000000000000; // 2**128
    const HASH_FR_ZERO_UINT256: u256 = 0;
    const HASH_FR_LEN_IN_BYTES: u8 = 48;
    const HASH_FR_SIZE_DOMAIN: u8 = 11;
    const HASH_FR_ONE: u8 = 1;
    const HASH_FR_TWO: u8 = 2;

    // Move verifier errors
    const ERROR_NB_PUBLIC_INPUTS: u64 = 1001;
    const ERROR_INPUTS_SIZE: u64 = 1002;
    const ERROR_PROOF_SIZE: u64 = 1003;
    const ERROR_PROOF_OPENING_SIZE: u64 = 1004;
    const ERROR_UNEXPECTED_VK_NB_CUSTOM_GATES_AMOUNT: u64 = 1005;
    const ERROR_PAIRING_KZG_CHECK: u64 = 1006;

    public fun verify(proof: vector<u256>, vk: u256, raw_public_inputs: vector<u8>) {
        let public_inputs = vector::empty<u256>();
        push_back(&mut public_inputs, vk);
        push_back(&mut public_inputs, bytes_to_uint256(sha2_256(raw_public_inputs)) & ((1 << 253) - 1));
        verify_inner(proof, public_inputs);
    }

    fun verify_inner(proof: vector<u256>, public_inputs: vector<u256>) {
        // technical assert to ensure that VK_NB_CUSTOM_GATES constant has not been changed
        assert!(VK_NB_CUSTOM_GATES == 1, ERROR_UNEXPECTED_VK_NB_CUSTOM_GATES_AMOUNT);

        // check number of public inputs
        assert!(length(&public_inputs) == VK_NB_PUBLIC_INPUTS, ERROR_NB_PUBLIC_INPUTS);

        // check size of the public_inputs
        let i = 0;

        while(i < VK_NB_PUBLIC_INPUTS) {
            assert!(R_MOD_MINUS_ONE > (*vector::borrow(&public_inputs, i)), ERROR_INPUTS_SIZE);
            i = i + 1
        };

        // check proof size
        assert!(length(&proof) * 32 == VK_NB_CUSTOM_GATES * 96 + 768, ERROR_PROOF_SIZE);

        // check size of proof openings
        i = 0;
        while(i < length(&proof)) {
            assert!(R_MOD_MINUS_ONE > (*vector::borrow(&proof, i)), ERROR_PROOF_OPENING_SIZE);
            i = i + 1
        };

        let vk = *vector::borrow(&public_inputs, 0);
        let public_inputs_digest = *vector::borrow(&public_inputs, 1);

        let gamma_non_reduced = derive_gamma(proof, vk, public_inputs_digest);
        let beta_non_reduced = derive_beta(gamma_non_reduced);
        let alpha_non_reduced = derive_alpha(proof, beta_non_reduced);
        let zeta_non_reduced = derive_zeta(proof, alpha_non_reduced);

        let gamma = gamma_non_reduced % R_MOD;
        let beta = beta_non_reduced % R_MOD;
        let alpha = alpha_non_reduced % R_MOD;
        let zeta = zeta_non_reduced % R_MOD;

        let zeta_bytes = vector::empty<u8>();
        append_value(&mut zeta_bytes, zeta, true, 32);
        let zeta_fr = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&zeta_bytes));
        let r_mod_minus_one_bytes = vector::empty<u8>();
        append_value(&mut r_mod_minus_one_bytes, R_MOD_MINUS_ONE, true, 32);
        let r_mod_minus_one_fr = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&r_mod_minus_one_bytes));
        let zeta_power_n_minus_one = add(&r_mod_minus_one_fr, &powSmall(zeta_fr, VK_DOMAIN_SIZE));

        let pic = compute_public_inputs_contribution(u256_to_fr(zeta), zeta_power_n_minus_one, public_inputs);

        let pic_custom_gates = compute_public_inputs_contribution_from_custom_gates(proof, u256_to_fr(zeta), zeta_power_n_minus_one, (length(&public_inputs) as u256));

        let l_pi = add(&pic, &pic_custom_gates);

        let alpha_square_lagrange_0 = compute_alpha_square_lagrange_0(zeta, zeta_power_n_minus_one, alpha);

        let opening_linearized_polynomial_zeta = verify_opening_linearized_polynomial(proof, beta, gamma, alpha, alpha_square_lagrange_0, l_pi);

        let folded_h = fold_h(proof, zeta, fr_to_u256(zeta_power_n_minus_one));

        let (linearized_polynomial_x, linearized_polynomial_y) = compute_commitment_linearized_polynomial(proof, beta, gamma, alpha, zeta, alpha_square_lagrange_0, folded_h);

        let gamma_kzg = compute_gamma_kzg(proof, zeta, linearized_polynomial_x, linearized_polynomial_y, opening_linearized_polynomial_zeta);

        let (state_folded_digest_x, state_folded_digest_y, state_folded_claimed_evals) = fold_state(proof, gamma_kzg, linearized_polynomial_x, linearized_polynomial_y, opening_linearized_polynomial_zeta);

        let (folded_digests, folded_qoutients) = batch_verify_multi_points(proof, zeta, gamma_kzg, state_folded_digest_x, state_folded_digest_y, state_folded_claimed_evals);
        let (fd_x, fd_y) = get_coordinates(folded_digests);
        let (fq_x, fq_y) = get_coordinates(folded_qoutients);

        check_pairing_kzg(fd_x, fd_y, fq_x, fq_y);
    }

    fun derive_gamma(proof: vector<u256>, vk: u256, public_inputs_digest: u256): u256 {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_GAMMA, true, 5);
        append_value(&mut preimage, VK_S1_COM_X, true, 32);
        append_value(&mut preimage, VK_S1_COM_Y, true, 32);
        append_value(&mut preimage, VK_S2_COM_X, true, 32);
        append_value(&mut preimage, VK_S2_COM_Y, true, 32);
        append_value(&mut preimage, VK_S3_COM_X, true, 32);
        append_value(&mut preimage, VK_S3_COM_Y, true, 32);
        append_value(&mut preimage, VK_QL_COM_X, true, 32);
        append_value(&mut preimage, VK_QL_COM_Y, true, 32);
        append_value(&mut preimage, VK_QR_COM_X, true, 32);
        append_value(&mut preimage, VK_QR_COM_Y, true, 32);
        append_value(&mut preimage, VK_QM_COM_X, true, 32);
        append_value(&mut preimage, VK_QM_COM_Y, true, 32);
        append_value(&mut preimage, VK_QO_COM_X, true, 32);
        append_value(&mut preimage, VK_QO_COM_Y, true, 32);
        append_value(&mut preimage, VK_QK_COM_X, true, 32);
        append_value(&mut preimage, VK_QK_COM_Y, true, 32);
        append_value(&mut preimage, VK_QCP_0_X, true, 32);
        append_value(&mut preimage, VK_QCP_0_Y, true, 32);
        append_value(&mut preimage, vk, true, 32);
        append_value(&mut preimage, public_inputs_digest, true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 0), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 1), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 2), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 3), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 4), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 5), true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    fun derive_beta(gamma_not_reduced: u256): u256 {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_BETA, true, 4);
        append_value(&mut preimage, gamma_not_reduced, true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    fun derive_alpha(proof: vector<u256>, beta_not_reduced: u256): u256 {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_ALPHA, true, 5);
        append_value(&mut preimage, beta_not_reduced, true, 32);
        // Bsb22Commitments
        append_value(&mut preimage, *vector::borrow(&proof, 25), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 26), true, 32);
        // [Z], the commitment to the grand product polynomial
        append_value(&mut preimage, *vector::borrow(&proof, 17), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 18), true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    fun derive_zeta(proof: vector<u256>, alpha_not_reduced: u256): u256 {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_ZETA, true, 4);
        append_value(&mut preimage, alpha_not_reduced, true, 32);
        // commitment to the quotient polynomial h
        append_value(&mut preimage, *vector::borrow(&proof, 6), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 7), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 8), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 9), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 10), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 11), true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    // TODO: simplify this function by splitting onto isolated sub-funcitons
    fun compute_public_inputs_contribution(zeta: Element<Fr>, zeta_power_n_minus_one: Element<Fr>, public_inputs: vector<u256>): Element<Fr> {
        // sum_pi_wo_api_commit function from Solidity contract
        let ins = public_inputs;
        let n = length(&ins);

        // batch_compute_lagranges_at_z
        let zn = mul(&zeta_power_n_minus_one, &u256_to_fr(VK_INV_DOMAIN_SIZE));
        let _mPtr = vector::empty<Element<Fr>>();
        let i = 0;
        let w = one<Fr>();
        let tmp: u256;
        let tmp_fr: Element<Fr>;
        while (i < n) {
            tmp = R_MOD - fr_to_u256(w);
            tmp_fr = add(&zeta, &u256_to_fr(tmp));
            push_back(&mut _mPtr, tmp_fr);

            w = mul(&w, &u256_to_fr(VK_OMEGA));

            i = i + 1
        };
        let ins_inner = copy _mPtr;

        let new_len = length(&_mPtr) - 1;
        trim(&mut _mPtr, new_len);

        // batch_invert
        push_back(&mut _mPtr, one<Fr>());

        let mPtr_input = copy _mPtr;

        reverse(&mut _mPtr);

        let mPtr = vector::empty<Element<Fr>>();
        let i = 0;
        let tmp;
        while (i < n) {
            let prev = vector::borrow(&_mPtr, i);
            let cur = vector::borrow(&ins_inner, i);
            tmp = mul(prev, cur);
            push_back(&mut mPtr, tmp);

            i = i + 1;
        };

        let inv = powSmall(pop_back(&mut mPtr), R_MOD - 2);

        reverse(&mut ins_inner);

        let ins_ = vector::empty<Element<Fr>>();
        let i = 0;
        let cur;
        while (i < n) {
            cur = mul(&inv, vector::borrow(&mPtr_input, i));
            push_back(&mut ins_, cur);

            inv = mul(&inv, vector::borrow(&ins_inner, i));
            i = i + 1;
        };

        reverse(&mut ins_);

        let li = vector::empty<Element<Fr>>();
        let i = 0;
        let tmp_fr;
        let w = one<Fr>();
        while (i < n) {
            tmp_fr = mul(&w, &mul(vector::borrow(&ins_, i), &zn));
            push_back(&mut li, tmp_fr);
            w = mul(&w, &u256_to_fr(VK_OMEGA));

            i = i + 1
        };

        let i = 0;
        let tmp;
        let pi_wo_commit = zero<Fr>();
        let left;
        let right;
        while (i < n) {
            left = *vector::borrow(&li, i);
            right = u256_to_fr(*vector::borrow(&ins, i));
            tmp = mul(&left, &right);
            pi_wo_commit = add(&pi_wo_commit, &tmp);

            i = i + 1
        };
        pi_wo_commit
    }

    fun compute_public_inputs_contribution_from_custom_gates(proof: vector<u256>, zeta: Element<Fr>, zeta_power_n_minus_one: Element<Fr>, nb_public_inputs: u256): Element<Fr> {
        let i = nb_public_inputs + VK_INDEX_COMMIT_API_0;

        let w = powSmall(u256_to_fr(VK_OMEGA), i);
        let i = add(&zeta, &u256_to_fr(R_MOD - fr_to_u256(w)));
        let w = mul(&w, &u256_to_fr(VK_INV_DOMAIN_SIZE));
        let i = powSmall(i, R_MOD - 2);
        let w = mul(&w, &i);
        let ith_lagrange = mul(&w, &zeta_power_n_minus_one);

        let calldataload_p: u256 = *vector::borrow(&proof, 25);
        let calldataload_p_32: u256 = *vector::borrow(&proof, 26);

        let preimage = vector::empty<u8>();
        append_value(&mut preimage, HASH_FR_ZERO_UINT256, true, 32);
        append_value(&mut preimage, HASH_FR_ZERO_UINT256, true, 32);
        append_value(&mut preimage, calldataload_p, true, 32);
        append_value(&mut preimage, calldataload_p_32, true, 32);
        append_value(&mut preimage, 0, true, 1);
        append_value(&mut preimage, (HASH_FR_LEN_IN_BYTES as u256), true, 1);
        append_value(&mut preimage, 0, true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x53, true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x2d, true, 1);
        append_value(&mut preimage, 0x50, true, 1);
        append_value(&mut preimage, 0x6c, true, 1);
        append_value(&mut preimage, 0x6f, true, 1);
        append_value(&mut preimage, 0x6e, true, 1);
        append_value(&mut preimage, 0x6b, true, 1);
        append_value(&mut preimage, (HASH_FR_SIZE_DOMAIN as u256), true, 1);
        let b0 = sha2_256(preimage);

        preimage = vector::empty<u8>();
        append_value(&mut preimage, bytes_to_uint256(b0), true, 32);
        append_value(&mut preimage, (HASH_FR_ONE as u256), true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x53, true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x2d, true, 1);
        append_value(&mut preimage, 0x50, true, 1);
        append_value(&mut preimage, 0x6c, true, 1);
        append_value(&mut preimage, 0x6f, true, 1);
        append_value(&mut preimage, 0x6e, true, 1);
        append_value(&mut preimage, 0x6b, true, 1);
        append_value(&mut preimage, (HASH_FR_SIZE_DOMAIN as u256), true, 1);
        let b1 = sha2_256(preimage);

        let preimage = vector::empty<u8>();
        append_value(&mut preimage, bytes_to_uint256(b0) ^ bytes_to_uint256(b1), true, 32);
        append_value(&mut preimage, (HASH_FR_TWO as u256), true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x53, true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x2d, true, 1);
        append_value(&mut preimage, 0x50, true, 1);
        append_value(&mut preimage, 0x6c, true, 1);
        append_value(&mut preimage, 0x6f, true, 1);
        append_value(&mut preimage, 0x6e, true, 1);
        append_value(&mut preimage, 0x6b, true, 1);
        append_value(&mut preimage, (HASH_FR_SIZE_DOMAIN as u256), true, 1);
        let hash = sha2_256(preimage);

        let b1_fr = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&u256_to_bytes(bytes_to_uint256(b1) % R_MOD)));
        let res = mul(&b1_fr, &u256_to_fr(HASH_FR_BB));
        let hash_shifted = bytes_to_uint256(hash) >> 128;
        let hash_fr = add(&res, &u256_to_fr(hash_shifted));
        let pi_commit = mul(&hash_fr, &ith_lagrange);
        pi_commit
    }

    fun compute_alpha_square_lagrange_0(zeta: u256, zeta_power_n_minus_one: Element<Fr>, alpha: u256): Element<Fr> {
        let den = add(&u256_to_fr(zeta), &u256_to_fr(R_MOD_MINUS_ONE));
        let den = powSmall(den, R_MOD - 2);
        let den = mul(&den, &u256_to_fr(VK_INV_DOMAIN_SIZE));
        let res = mul(&den, &zeta_power_n_minus_one);
        let res = mul(&res, &u256_to_fr(alpha));
        let alpha_square_lagrange_0 = mul(&res, &u256_to_fr(alpha));
        alpha_square_lagrange_0
    }

    fun verify_opening_linearized_polynomial(proof: vector<u256>, beta: u256, gamma: u256, alpha: u256, alpha_square_lagrange_0: Element<Fr>, pic: Element<Fr>): u256 {
        let s1 = mul(&u256_to_fr(*vector::borrow(&proof, 15)), &u256_to_fr(beta));
        let s1 = add(&s1, &u256_to_fr(gamma));
        let s1 = add(&s1, &u256_to_fr(*vector::borrow(&proof, 12)));

        let s2 = mul(&u256_to_fr(*vector::borrow(&proof, 16)), &u256_to_fr(beta));
        let s2 = add(&s2, &u256_to_fr(gamma));
        let s2 = add(&s2, &u256_to_fr(*vector::borrow(&proof, 13)));

        let o = add(&u256_to_fr(*vector::borrow(&proof, 14)), &u256_to_fr(gamma));

        let s1 = mul(&s1, &s2);
        let s1 = mul(&s1, &o);
        let s1 = mul(&s1, &u256_to_fr(alpha));
        let s1 = mul(&s1, &u256_to_fr(*vector::borrow(&proof, 19)));

        let s1 = add(&s1, &pic);
        let s2 = (R_MOD - fr_to_u256(alpha_square_lagrange_0)) % R_MOD;
        let s1 = add(&s1, &u256_to_fr(s2));
        let s1 = (R_MOD - fr_to_u256(s1)) % R_MOD;

        s1
    }

    fun compute_gamma_kzg(proof: vector<u256>, zeta: u256, linearized_polynomial_x: u256, linearized_polynomial_y: u256, opening_linearized_polynomial_zeta: u256): u256  {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_GAMMA_KZG, true, 5);
        append_value(&mut preimage, zeta, true, 32);
        append_value(&mut preimage, linearized_polynomial_x, true, 32);
        append_value(&mut preimage, linearized_polynomial_y, true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 0), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 1), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 2), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 3), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 4), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 5), true, 32);
        append_value(&mut preimage, VK_S1_COM_X, true, 32);
        append_value(&mut preimage, VK_S1_COM_Y, true, 32);
        append_value(&mut preimage, VK_S2_COM_X, true, 32);
        append_value(&mut preimage, VK_S2_COM_Y, true, 32);
        append_value(&mut preimage, VK_QCP_0_X, true, 32);
        append_value(&mut preimage, VK_QCP_0_Y, true, 32);
        append_value(&mut preimage, opening_linearized_polynomial_zeta, true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 12), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 13), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 14), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 15), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 16), true, 32);
        // Breaking change happens if VK_NB_CUSTOM_GATES != 1.
        // In original Solidity contract the number of proof chunks appended is computed as VK_NB_CUSTOM_GATES * 32)
        append_value(&mut preimage, *vector::borrow(&proof, 24), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 19), true, 32);

        let hash = sha2_256(preimage);
        let hash_reduced = bytes_to_uint256(hash) % R_MOD;
        hash_reduced
    }

    fun check_pairing_kzg(folded_digests_x: u256, folded_digests_y: u256, folded_quotients_x: u256, folded_quotients_y: u256) {
        // G1
        let pairing_input_0: u256 = folded_digests_x;
        let pairing_input_1: u256 = folded_digests_y;
        // G2
        let pairing_input_2: u256 = G2_SRS_0_X_0;
        let pairing_input_3: u256 = G2_SRS_0_X_1;
        let pairing_input_4: u256 = G2_SRS_0_Y_0;
        let pairing_input_5: u256 = G2_SRS_0_Y_1;
        // G1
        let pairing_input_6: u256 = folded_quotients_x;
        let pairing_input_7: u256 = folded_quotients_y;
        // G2
        let pairing_input_8: u256 = G2_SRS_1_X_0;
        let pairing_input_9: u256 = G2_SRS_1_X_1;
        let pairing_input_10: u256 = G2_SRS_1_Y_0;
        let pairing_input_11: u256 = G2_SRS_1_Y_1;

        let g1_elements = vector::empty<Element<G1>>();
        push_back(&mut g1_elements, new_g1(pairing_input_0, pairing_input_1));
        push_back(&mut g1_elements, new_g1(pairing_input_6, pairing_input_7));

        let g2_elements = vector::empty<Element<G2>>();
        push_back(&mut g2_elements, new_g2(pairing_input_2, pairing_input_3, pairing_input_4, pairing_input_5));
        push_back(&mut g2_elements, new_g2(pairing_input_8, pairing_input_9, pairing_input_10, pairing_input_11));
        let gt_element = multi_pairing<G1, G2, Gt>(&g1_elements, &g2_elements);
        assert!(eq(&gt_element, &zero<Gt>()), ERROR_PAIRING_KZG_CHECK);
    }

    // TODO: validate verificaion on various proofs since there are places where arithmetic overflow may happen
    fun batch_verify_multi_points(proof: vector<u256>, zeta: u256, gamma_kzg: u256, state_folded_digest_x: u256, state_folded_digest_y: u256, state_folded_claimed_evals: u256): (Element<G1>, Element<G1>) {
        let proof_batch_opening_at_zeta_x: u256 = *vector::borrow(&proof, 20);
        let proof_batch_opening_at_zeta_y: u256 = *vector::borrow(&proof, 21);
        let proof_grand_product_commitment_x: u256 = *vector::borrow(&proof, 17);
        let proof_grand_product_commitment_y: u256 = *vector::borrow(&proof, 18);
        let proof_opening_at_zeta_omega_x: u256 = *vector::borrow(&proof, 22);
        let proof_opening_at_zeta_omega_y: u256 = *vector::borrow(&proof, 23);
        let proof_grand_product_at_zeta_omega: u256 = *vector::borrow(&proof, 19);

        let preimage = vector::empty<u8>();
        append_value(&mut preimage, state_folded_digest_x, true, 32);
        append_value(&mut preimage, state_folded_digest_y, true, 32);
        append_value(&mut preimage, proof_batch_opening_at_zeta_x, true, 32);
        append_value(&mut preimage, proof_batch_opening_at_zeta_y, true, 32);
        append_value(&mut preimage, proof_grand_product_commitment_x, true, 32);
        append_value(&mut preimage, proof_grand_product_commitment_y, true, 32);
        append_value(&mut preimage, proof_opening_at_zeta_omega_x, true, 32);
        append_value(&mut preimage, proof_opening_at_zeta_omega_y, true, 32);
        append_value(&mut preimage, zeta, true, 32);
        append_value(&mut preimage, gamma_kzg, true, 32);

        let hash = sha2_256(preimage);
        let random = bytes_to_uint256(hash) % R_MOD;

        let proof_opening_at_zeta_omega = new_g1(proof_opening_at_zeta_omega_x, proof_opening_at_zeta_omega_y);
        let proof_batch_opening_at_zeta = new_g1(proof_batch_opening_at_zeta_x, proof_batch_opening_at_zeta_y);
        let folded_quotients = point_acc_mul(proof_opening_at_zeta_omega, u256_to_fr(random), proof_batch_opening_at_zeta);
        let folded_quotients = prepare_pairing_g1_input(folded_quotients, P_MOD);

        let proof_grand_product_commitment = new_g1(proof_grand_product_commitment_x, proof_grand_product_commitment_y);
        let state_folded_digests = new_g1(state_folded_digest_x, state_folded_digest_y);
        let folded_digests = point_acc_mul(proof_grand_product_commitment, u256_to_fr(random), state_folded_digests);

        let folded_evals = fr_acc_mul(state_folded_claimed_evals, proof_grand_product_at_zeta_omega, random);

        let g1_srs = new_g1(G1_SRS_X, G1_SRS_Y);
        let folded_evals_commit = scalar_mul(&g1_srs, &folded_evals);

        let folded_evals_commit = prepare_pairing_g1_input(folded_evals_commit, P_MOD);

        let folded_digests = add(&folded_digests, &folded_evals_commit);

        let folded_points_quotients = scalar_mul(&new_g1(proof_batch_opening_at_zeta_x, proof_batch_opening_at_zeta_y), &u256_to_fr(zeta));

        let zeta_omega = mul(&u256_to_fr(zeta), &u256_to_fr(VK_OMEGA));
        let random = mul(&u256_to_fr(random), &zeta_omega);

        let folded_points_quotients = point_acc_mul(proof_opening_at_zeta_omega, random, folded_points_quotients);

        let folded_digests = add(&folded_digests, &folded_points_quotients);

        (folded_digests, folded_quotients)
    }

    fun fold_h(proof: vector<u256>, zeta: u256, zeta_power_n_minus_one: u256): Element<G1> {
        let n_plus_two = VK_DOMAIN_SIZE + 2;
        let proof_h_2_x: u256 = *vector::borrow(&proof, 10);
        let proof_h_2_y: u256 = *vector::borrow(&proof, 11);
        let proof_h_1_x: u256 = *vector::borrow(&proof, 8);
        let proof_h_1_y: u256 = *vector::borrow(&proof, 9);
        let proof_h_0_x: u256 = *vector::borrow(&proof, 6);
        let proof_h_0_y: u256 = *vector::borrow(&proof, 7);

        let zeta_power_n_plus_two = powSmall(u256_to_fr(zeta), n_plus_two);
        let folded_h = scalar_mul(&new_g1(proof_h_2_x, proof_h_2_y), &zeta_power_n_plus_two);
        let folded_h = add(&folded_h, &new_g1(proof_h_1_x, proof_h_1_y));
        let folded_h = scalar_mul(&folded_h, &zeta_power_n_plus_two);
        let folded_h = add(&folded_h, &new_g1(proof_h_0_x, proof_h_0_y));
        let folded_h = scalar_mul(&folded_h, &u256_to_fr(zeta_power_n_minus_one));
        let folded_h = prepare_pairing_g1_input(folded_h, P_MOD);
        folded_h
    }

    fun fold_state(proof: vector<u256>, gamma_kzg: u256, linearized_polynomial_x: u256, linearized_polynomial_y: u256, opening_linearized_polynomial_zeta: u256): (u256, u256, u256) {
        let proof_l_com_x: u256 = *vector::borrow(&proof, 0);
        let proof_l_com_y: u256 = *vector::borrow(&proof, 1);
        let proof_l_at_zeta: u256 = *vector::borrow(&proof, 12);
        let proof_r_at_zeta: u256 = *vector::borrow(&proof, 13);
        let proof_o_at_zeta: u256 = *vector::borrow(&proof, 14);
        let proof_s1_at_zeta: u256 = *vector::borrow(&proof, 15);
        let proof_s2_at_zeta: u256 = *vector::borrow(&proof, 16);
        let proof_opening_qcp_at_zeta: u256 = *vector::borrow(&proof, 24);

        let proof_r_com_x: u256 = *vector::borrow(&proof, 2);
        let proof_r_com_y: u256 = *vector::borrow(&proof, 3);
        let proof_o_com_x: u256 = *vector::borrow(&proof, 4);
        let proof_o_com_y: u256 = *vector::borrow(&proof, 5);

        let state_folded_digest = point_acc_mul(new_g1(proof_l_com_x, proof_l_com_y), u256_to_fr(gamma_kzg), new_g1(linearized_polynomial_x, linearized_polynomial_y));

        let state_folded_claimed_values = fr_acc_mul(opening_linearized_polynomial_zeta, proof_l_at_zeta, gamma_kzg);

        let acc_gamma = mul(&u256_to_fr(gamma_kzg), &u256_to_fr(gamma_kzg));

        let state_folded_digest = point_acc_mul(new_g1(proof_r_com_x, proof_r_com_y), acc_gamma, state_folded_digest);

        let state_folded_claimed_values = fr_acc_mul(fr_to_u256(state_folded_claimed_values), proof_r_at_zeta, fr_to_u256(acc_gamma));

        let acc_gamma = mul(&acc_gamma, &u256_to_fr(gamma_kzg));

        let state_folded_digest = point_acc_mul(new_g1(proof_o_com_x, proof_o_com_y), acc_gamma, state_folded_digest);

        let state_folded_claimed_values = fr_acc_mul(fr_to_u256(state_folded_claimed_values), proof_o_at_zeta, fr_to_u256(acc_gamma));

        let acc_gamma = mul(&acc_gamma, &u256_to_fr(gamma_kzg));

        let state_folded_digest = point_acc_mul(new_g1(VK_S1_COM_X, VK_S1_COM_Y), acc_gamma, state_folded_digest);

        let state_folded_claimed_values = fr_acc_mul(fr_to_u256(state_folded_claimed_values), proof_s1_at_zeta, fr_to_u256(acc_gamma));

        let acc_gamma = mul(&acc_gamma, &u256_to_fr(gamma_kzg));

        let state_folded_digest = point_acc_mul(new_g1(VK_S2_COM_X, VK_S2_COM_Y), acc_gamma, state_folded_digest);

        let state_folded_claimed_values = fr_acc_mul(fr_to_u256(state_folded_claimed_values), proof_s2_at_zeta, fr_to_u256(acc_gamma));

        let acc_gamma = mul(&acc_gamma, &u256_to_fr(gamma_kzg));

        let state_folded_digest = point_acc_mul(new_g1(VK_QCP_0_X, VK_QCP_0_Y), acc_gamma, state_folded_digest);

        let state_folded_claimed_values = fr_acc_mul(fr_to_u256(state_folded_claimed_values), proof_opening_qcp_at_zeta, fr_to_u256(acc_gamma));

        let (a, b) = get_coordinates(state_folded_digest);

        (a, b, fr_to_u256(state_folded_claimed_values))
    }

    fun compute_commitment_linearized_polynomial(
        proof: vector<u256>,
        state_beta: u256,
        state_gamma: u256,
        state_alpha: u256,
        state_zeta: u256,
        alpha_square_lagrange_0: Element<Fr>,
        folded_h: Element<G1>,
    ): (u256, u256) {
        let proof_grand_product_at_zeta_omega: u256 = *vector::borrow(&proof, 19);
        let proof_s1_at_zeta: u256 = *vector::borrow(&proof, 15);
        let proof_l_at_zeta: u256 = *vector::borrow(&proof, 12);
        let proof_s2_at_zeta: u256 = *vector::borrow(&proof, 16);
        let proof_r_at_zeta: u256 = *vector::borrow(&proof, 13);
        let proof_o_at_zeta: u256 = *vector::borrow(&proof, 14);

        let qcp_opening_at_zeta = *vector::borrow(&proof, 24);
        let bsb_commitment_x = *vector::borrow(&proof, 25);
        let bsb_commitment_y = *vector::borrow(&proof, 26);
        let proof_grand_product_commitment_x: u256 = *vector::borrow(&proof, 17);
        let proof_grand_product_commitment_y: u256 = *vector::borrow(&proof, 18);

        let bsb_commitment = vector::empty<Element<G1>>();
        push_back(&mut bsb_commitment, new_g1(bsb_commitment_x, bsb_commitment_y));

        assert!(length(&bsb_commitment) == VK_NB_CUSTOM_GATES, ERROR_UNEXPECTED_VK_NB_CUSTOM_GATES_AMOUNT);

        let u = mul(&u256_to_fr(proof_grand_product_at_zeta_omega), &u256_to_fr(state_beta));
        let v = mul(&u256_to_fr(state_beta), &u256_to_fr(proof_s1_at_zeta));

        let v = add(&v, &u256_to_fr(proof_l_at_zeta));
        let v = add(&v, &u256_to_fr(state_gamma));

        let w = mul(&u256_to_fr(state_beta), &u256_to_fr(proof_s2_at_zeta));
        let w = add(&w, &u256_to_fr(proof_r_at_zeta));
        let w = add(&w, &u256_to_fr(state_gamma));

        let s1 = mul(&u, &v);
        let s1 = mul(&s1, &w);
        let s1 = mul(&s1, &u256_to_fr(state_alpha));

        let coset_square = mul(&u256_to_fr(VK_COSET_SHIFT), &u256_to_fr(VK_COSET_SHIFT));
        let betazeta = mul(&u256_to_fr(state_beta), &u256_to_fr(state_zeta));
        let u = add(&betazeta, &u256_to_fr(proof_l_at_zeta));
        let u = add(&u, &u256_to_fr(state_gamma));

        let v = mul(&betazeta, &u256_to_fr(VK_COSET_SHIFT));
        let v = add(&v, &u256_to_fr(proof_r_at_zeta));
        let v = add(&v, &u256_to_fr(state_gamma));

        let w = mul(&betazeta, &coset_square);
        let w = add(&w, &u256_to_fr(proof_o_at_zeta));
        let w = add(&w, &u256_to_fr(state_gamma));

        let s2 = mul(&u, &v);
        let s2 = mul(&s2, &w);
        let s2 = R_MOD - fr_to_u256(s2);
        let s2 = mul(&u256_to_fr(s2), &u256_to_fr(state_alpha));
        let s2 = add(&s2, &alpha_square_lagrange_0);

        // compute_commitment_linearised_polynomial_ec
        let state_linearized_polynomial = new_g1(VK_QL_COM_X, VK_QL_COM_Y);
        let state_linearized_polynomial = scalar_mul(&state_linearized_polynomial, &u256_to_fr(proof_l_at_zeta));

        let state_linearized_polynomial = point_acc_mul(new_g1(VK_QR_COM_X, VK_QR_COM_Y), u256_to_fr(proof_r_at_zeta), state_linearized_polynomial);

        let rl = mul(&u256_to_fr(proof_l_at_zeta), &u256_to_fr(proof_r_at_zeta));

        let state_linearized_polynomial = point_acc_mul(new_g1(VK_QM_COM_X, VK_QM_COM_Y), rl, state_linearized_polynomial);

        let state_linearized_polynomial = point_acc_mul(new_g1(VK_QO_COM_X, VK_QO_COM_Y), u256_to_fr(proof_o_at_zeta), state_linearized_polynomial);

        let state_linearized_polynomial = add(&new_g1(VK_QK_COM_X, VK_QK_COM_Y), &state_linearized_polynomial);

        let i: u64 = 0;
        while (i < VK_NB_CUSTOM_GATES) {
            state_linearized_polynomial = point_acc_mul(*vector::borrow(&bsb_commitment, i), u256_to_fr(qcp_opening_at_zeta), state_linearized_polynomial);
            i = i + 1
        };
        let state_linearized_polynomial = point_acc_mul(new_g1(VK_S3_COM_X, VK_S3_COM_Y), s1, state_linearized_polynomial);
        let state_linearized_polynomial = point_acc_mul(new_g1(proof_grand_product_commitment_x, proof_grand_product_commitment_y), s2, state_linearized_polynomial);
        let state_linearized_polynomial = add(&state_linearized_polynomial, &folded_h);
        let (x, y) = get_coordinates(state_linearized_polynomial);
        (unset_first_bit(x), unset_first_bit(y))
    }

    #[test_only]
    public fun get_proof(): vector<u256> {
        let proof = vector::empty<u256>();
        push_back(&mut proof, Proof_chunk_0);
        push_back(&mut proof, Proof_chunk_1);
        push_back(&mut proof, Proof_chunk_2);
        push_back(&mut proof, Proof_chunk_3);
        push_back(&mut proof, Proof_chunk_4);
        push_back(&mut proof, Proof_chunk_5);
        push_back(&mut proof, Proof_chunk_6);
        push_back(&mut proof, Proof_chunk_7);
        push_back(&mut proof, Proof_chunk_8);
        push_back(&mut proof, Proof_chunk_9);
        push_back(&mut proof, Proof_chunk_10);
        push_back(&mut proof, Proof_chunk_11);
        push_back(&mut proof, Proof_chunk_12);
        push_back(&mut proof, Proof_chunk_13);
        push_back(&mut proof, Proof_chunk_14);
        push_back(&mut proof, Proof_chunk_15);
        push_back(&mut proof, Proof_chunk_16);
        push_back(&mut proof, Proof_chunk_17);
        push_back(&mut proof, Proof_chunk_18);
        push_back(&mut proof, Proof_chunk_19);
        push_back(&mut proof, Proof_chunk_20);
        push_back(&mut proof, Proof_chunk_21);
        push_back(&mut proof, Proof_chunk_22);
        push_back(&mut proof, Proof_chunk_23);
        push_back(&mut proof, Proof_chunk_24);
        push_back(&mut proof, Proof_chunk_25);
        push_back(&mut proof, Proof_chunk_26);
        proof
    }

    #[test_only]
    public fun get_public_inputs(): vector<u256> {
        let public_inputs = vector::empty<u256>();
        push_back(&mut public_inputs, SphinxInclusionProofVk);
        push_back(&mut public_inputs, SphinxPublicValuesHash);
        public_inputs
    }

    #[test]
    public fun test_pairing_kzg_check() {
        let folded_digests_x: u256 = 0x08b99791fe52556d6763cc2ef120620e81e6403dc1aea7b14be1d96f1f53cb57;
        let folded_digests_y: u256 = 0x0bb5831359b594a93730d4fcd7ce5bf1e89c589f0c230465e5dc993694c5cda3;

        let folded_quotients_x: u256 = 0x1372be68afe235fcad22b0f5bbee8120b4144cf12e8be05e0fee58b2edaefb99;
        let folded_quotients_y: u256 = 0x009eed110f00d9b208e8a9b6fd71e471e6180c17fb58a9b09693da3c0b7a8872;

        check_pairing_kzg(folded_digests_x, folded_digests_y, folded_quotients_x, folded_quotients_y);
    }

    #[test]
    public fun test_compute_zeta_power_r_minus_one() {
        let zeta = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"16497e15231e0304a0f5307d0a4d3b874bc4a33bb786c88344ce3206a952f61a"));
        let r_mod_minus_one_element = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"));
        let zeta_power_n_minus_one = add(&r_mod_minus_one_element, &powSmall(zeta, VK_DOMAIN_SIZE));
        assert!(&serialize<Fr, FormatFrMsb>(&zeta_power_n_minus_one) == &x"0183624d8a1f2df2d1bc0ea04c97a743b1031835afb4fc9fb25e88f37780deb7", 1);
    }

    #[test]
    public fun test_verify_inner() {
        let proof = get_proof();
        let public_inputs = get_public_inputs();
        verify_inner(proof, public_inputs);
    }

    #[test]
    public fun test_compute_public_values_hash() {
        let raw_public_inputs = SphinxRawPublicValues;
        let pv_hash = bytes_to_uint256(sha2_256(raw_public_inputs)) & ((1 << 253) - 1);
        assert!(pv_hash == SphinxPublicValuesHash, 1);
    }

    const SphinxInclusionProofVk: u256 = 0x00092f91616b81e394f434c4c8b330b44a313c51bb54a89a1bf9254ac05b0f6f;
    const SphinxRawPublicValues: vector<u8> = x"3700000059000000";
    const SphinxPublicValuesHash: u256 = 0x190e5a3ed690bd3b533c087ef7339d00e25113d217f7dac4575a01b79dacd553;
    const Proof_chunk_0: u256 = 0x0991492d32f5f314d59184b7b5ee7f508cda6aac56d4ca3e7be611a9690881d2;
    const Proof_chunk_1: u256 = 0x29b59493ae8b15e9a78af1a0bb5d7dbe0b89c01dfc037358067b12f4a56a5f4c;
    const Proof_chunk_2: u256 = 0x08383cc20d20acd891dd46ae2c7061c9749e0d2c51e947486a5d8253667029fd;
    const Proof_chunk_3: u256 = 0x061728ada00badd62aff7dd3054dbe64f9d63c56b2d7ef86e80a6886a3456441;
    const Proof_chunk_4: u256 = 0x189b9da835c3f1bda944ef8b3c67b96a2ed099b71b3496e2664ed3a4224df47e;
    const Proof_chunk_5: u256 = 0x2600f610719f09ac469644f87744aef187c4cebd49414aada587a3b8e57e1583;
    const Proof_chunk_6: u256 = 0x2d5d178ab6cef3a22c66edea8563928c859237e857ba99fff600139dbe089ae2;
    const Proof_chunk_7: u256 = 0x085408fc1916ff6fda8e6bcd2c11fe72525fac1e6f5b6940aa9cfd122612df64;
    const Proof_chunk_8: u256 = 0x10fa08fc806f09138ef1c7d40c8501e203424787988a399f31d3de3c650382f1;
    const Proof_chunk_9: u256 = 0x1ca0d642b92f08cdbbf7c0b4715eecd0968cdf8d4f32d14b62cf8db267d9c1a0;
    const Proof_chunk_10: u256 = 0x24a19c3d65822a5eddbd7038e34be95ed43ae85afaf6060a6af29ccedbb48a7a;
    const Proof_chunk_11: u256 = 0x23b924122297dff3edbd576048f75c9d942f64db0e6da70103a335e7a2404b57;
    const Proof_chunk_12: u256 = 0x16077f36b6317dd96646f6edc1cccb5eed778722206b454a7ce1d163419558e9;
    const Proof_chunk_13: u256 = 0x069256a9e449f9f0a951c4d4c173df85f75f8b0d07362f5d9cb4d67c3b38cc8c;
    const Proof_chunk_14: u256 = 0x1f28969ca82e61b8ebbca23908856e8136116ab960f8d01f77b6d78b064fea95;
    const Proof_chunk_15: u256 = 0x2e6666aee09c138d053d0c9afd8bd6005d571efc1f0818c441df2560d95a17c5;
    const Proof_chunk_16: u256 = 0x234042767447ca76512f28e42dc97d6e61b4b997f51659d0ea78e848a5ae172b;
    const Proof_chunk_17: u256 = 0x011d659770b6190e643227601611987ede55e26e38b4125f5588ad99b2de28e1;
    const Proof_chunk_18: u256 = 0x2e745f6a7e3f42e691231f74538ec20f822973c98c106d2c7058fadb3f4621b4;
    const Proof_chunk_19: u256 = 0x21d1d3fe938a58202b6fbca640a2857b64b8177be4cdfdeda52eaf5f6b85daf4;
    const Proof_chunk_20: u256 = 0x186f35746e36cf151f1f96513c35651cb176fb6b17f164b990cf6c9840f88cb9;
    const Proof_chunk_21: u256 = 0x1e35a866d7dee7d0704802c2058ac3174d55b3903ac57762bc8f930adc6f1e19;
    const Proof_chunk_22: u256 = 0x11bf6c5193297c42be7697054a984e1bd5a28aac17f33383cd370c7b5d1c4662;
    const Proof_chunk_23: u256 = 0x23d525ba9be78ba29b7643d162c55c29cc2e5d06c05b9ecd4a3d33c79d827acb;
    const Proof_chunk_24: u256 = 0x1e6a6ffc29cfcb71e29560dbc2cf3cefb07aa60c4dd9628e7ee9289908b89384;
    const Proof_chunk_25: u256 = 0x2c61a697f75645f4f2f06c92453a2289f68fb8305b2dd827f5f839da3e680c03;
    const Proof_chunk_26: u256 = 0x0c41851d410224db7bb85c98ca29e04e8e7df918d963b52ab95737e75635a47a;
}
