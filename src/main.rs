mod sets;
mod utils;

use clap::Parser;

#[derive(Parser)]
#[command(name = "cryptopals", about = "Cryptopals challenge solutions")]
struct Cli {
    /// Challenge number to run (e.g. 3, 16). Omit to run all challenges.
    challenge: Option<u32>,

    /// Run all challenges in the given set number instead (e.g. --set 1)
    #[arg(short, long, conflicts_with = "challenge")]
    set: Option<u32>,
}

fn main() {
    let cli = Cli::parse();

    match (cli.challenge, cli.set) {
        (Some(n), _) => run_challenge(n),
        (_, Some(s)) => run_set(s),
        (None, None) => {
            run_set(1);
            run_set(2);
        }
    }
}

fn run_challenge(n: u32) {
    match n {
        1 => sets::set1::challenge_one(),
        2 => sets::set1::challenge_two(),
        3 => sets::set1::challenge_three(),
        4 => sets::set1::challenge_four(),
        5 => sets::set1::challenge_five(),
        6 => sets::set1::challenge_six(),
        7 => sets::set1::challenge_seven(),
        8 => sets::set1::challenge_eight(),
        9 => sets::set2::challenge_nine(),
        10 => sets::set2::challenge_ten(),
        11 => sets::set2::challenge_eleven(),
        12 => sets::set2::challenge_twelve(),
        13 => sets::set2::challenge_thirteen(),
        14 => sets::set2::challenge_fourteen(),
        16 => sets::set2::challenge_sixteen(),
        17 => sets::set3::challenge_seventeen(),
        18 => sets::set3::challenge_eighteen(),
        20 => sets::set3::challenge_twenty(),
        21 => sets::set3::challenge_twentyone(),
        22 => sets::set3::challenge_twentytwo(),
        23 => sets::set3::challenge_twentythree(),
        _ => eprintln!("Challenge {} not found", n),
    }
}

fn run_set(s: u32) {
    match s {
        1 => sets::set1::run_all(),
        2 => sets::set2::run_all(),
        3 => sets::set3::run_all(),
        _ => eprintln!("Set {} not found", s),
    }
}
