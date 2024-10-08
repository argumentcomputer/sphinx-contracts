use sha2::{Digest, Sha256};
use sphinx_sdk::utils::setup_logger;
use sphinx_sdk::{
    HashableKey, ProverClient, SphinxProofWithPublicValues, SphinxStdin, SphinxVerifyingKey,
};

fn print_solidity(vk: &SphinxVerifyingKey, proof: &SphinxProofWithPublicValues) {
    println!("Solidity");
    println!();
    println!(
        "bytes private TestVerifierKey = abi.encodePacked(hex\"{}\");",
        vk.bytes32().to_string().as_str()[2..].to_string()
    );
    println!(
        "bytes private TestPublicValues = abi.encodePacked(hex\"{}\");",
        proof.public_values.bytes().to_string().as_str()[2..].to_string()
    );
    match &proof.proof {
        sphinx_sdk::SphinxProof::Plonk(pr) => {
            println!(
                "bytes private TestProof = abi.encodePacked(hex\"{}\");",
                format!(
                    "{}{}",
                    hex::encode(&pr.plonk_vkey_hash[..4]),
                    pr.encoded_proof,
                )
            );
        }
        _ => unreachable!(),
    };

    println!();
}

fn print_move(vk: &SphinxVerifyingKey, proof: &SphinxProofWithPublicValues) {
    println!("Move");
    println!();
    println!(
        "const SphinxInclusionProofVk: u256 = 0x{};",
        vk.bytes32().to_string().as_str()[2..].to_string()
    );

    let raw_public_values =
        hex::decode(proof.public_values.bytes().to_string().as_str()[2..].to_string()).unwrap();

    println!(
        "const SphinxRawPublicValues: vector<u8> = x\"{}\";",
        hex::encode(&raw_public_values).replace("\"", "")
    );

    let res = Sha256::digest(&raw_public_values);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&res);
    hash[0] &= 0x1f;

    println!(
        "const SphinxPublicValuesHash: u256 = 0x{};",
        hex::encode(&hash).replace("\"", "")
    );

    match &proof.proof {
        sphinx_sdk::SphinxProof::Plonk(pr) => {
            let proof_chunks = pr
                .encoded_proof
                .chars()
                .collect::<Vec<char>>()
                .chunks(64)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<String>>();

            for (i, chunk) in proof_chunks.into_iter().enumerate() {
                println!("const Proof_chunk_{}: u256 = 0x{};", i, chunk);
            }
        }
        _ => unreachable!(),
    };
}

fn main() {
    setup_logger();
    let prover = ProverClient::new();
    let mut stdin = SphinxStdin::new();
    stdin.write(&Vec::<u8>::new());

    let (pk, vk) = prover.setup(include_bytes!("fibonacci-elf/riscv32im-succinct-zkvm-elf"));
    let proof = prover.prove(&pk, stdin).plonk().run().unwrap();
    prover.verify(&proof, &vk).unwrap();

    print_solidity(&vk, &proof);
    print_move(&vk, &proof);
}
