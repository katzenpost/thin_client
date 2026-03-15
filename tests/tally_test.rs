// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Tally protocol integration tests.
//!
//! Tests the distributed meeting-availability poll over a live mixnet.
//!
//! # Running tests one at a time with output
//!
//! cargo test --test tally_test test_tally_two_voters         -- --nocapture
//! cargo test --test tally_test test_tally_three_voters       -- --nocapture
//! cargo test --test tally_test test_tally_ballot_update      -- --nocapture
//! cargo test --test tally_test test_tally_best_slot          -- --nocapture

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use katzenpost_thin_client::tally::{Availability, TallyPoll, Slot};
use katzenpost_thin_client::persistent::PigeonholeClient;
use katzenpost_thin_client::{Config, ThinClient};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

async fn setup_client(label: &str) -> Result<Arc<ThinClient>, Box<dyn std::error::Error>> {
    println!("[{}] ThinClient::new ...", label);
    let config = Config::new("testdata/thinclient.toml")?;
    let client = ThinClient::new(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("[{}] setup_client done", label);
    Ok(client)
}

fn two_slots() -> Vec<Slot> {
    vec![
        Slot::new("mon-9", "Monday 09:00"),
        Slot::new("tue-9", "Tuesday 09:00"),
    ]
}

fn three_slots() -> Vec<Slot> {
    vec![
        Slot::new("mon-9", "Monday 09:00"),
        Slot::new("tue-9", "Tuesday 09:00"),
        Slot::new("wed-9", "Wednesday 09:00"),
    ]
}

// ---------------------------------------------------------------------------
// Test 1: creator + one voter, verify tally
// ---------------------------------------------------------------------------

/// Alice creates a poll with two slots and votes Yes on both.
/// Bob joins, receives Alice's CreatePoll, then casts his ballot.
/// Alice receives Bob's ballot and verifies the tally is correct.
#[tokio::test]
async fn test_tally_two_voters() {
    println!("\n=== Test: Tally poll with Alice (creator) and Bob ===");

    let (alice_thin, bob_thin) = tokio::join!(
        setup_client("alice"),
        setup_client("bob"),
    );
    let alice_thin = alice_thin.expect("Alice ThinClient");
    let bob_thin   = bob_thin.expect("Bob ThinClient");

    let alice_ph = PigeonholeClient::new_in_memory(alice_thin.clone()).expect("Alice PigeonholeClient");
    let bob_ph   = PigeonholeClient::new_in_memory(bob_thin.clone()).expect("Bob PigeonholeClient");

    println!("\n--- Alice creates the poll ---");
    let mut alice_poll = TallyPoll::new_poll(
        &alice_ph,
        "standup-2v",
        "Alice",
        "Weekly standup",
        two_slots(),
    ).await.expect("Alice new_poll");

    let alice_intro = alice_poll.my_introduction();

    println!("\n--- Bob joins and receives Alice's CreatePoll ---");
    let mut bob_poll = TallyPoll::join_poll(
        &bob_ph,
        "standup-2v",
        "Bob",
        &alice_intro,
    ).await.expect("Bob join_poll");

    // Bob receives Alice's CreatePoll and folds it into his state.
    bob_poll.receive_one_and_apply().await.expect("Bob receive CreatePoll");
    assert_eq!(bob_poll.poll_state().title, "Weekly standup");
    assert_eq!(bob_poll.poll_state().slots.len(), 2);
    println!("✓ Bob sees poll: '{}' with {} slots",
        bob_poll.poll_state().title,
        bob_poll.poll_state().slots.len());

    println!("\n--- Exchange introductions ---");
    let bob_intro = bob_poll.my_introduction();
    alice_poll.add_member(&alice_ph, &bob_intro).expect("Alice add Bob");
    // Bob already has Alice from join_poll; only Alice needs to add Bob.

    println!("\n--- Alice and Bob cast ballots in parallel ---");
    let alice_votes = HashMap::from([
        ("mon-9".to_string(), Availability::Yes),
        ("tue-9".to_string(), Availability::Maybe),
    ]);
    let bob_votes = HashMap::from([
        ("mon-9".to_string(), Availability::No),
        ("tue-9".to_string(), Availability::Yes),
    ]);
    let (r1, r2) = tokio::join!(
        alice_poll.cast_ballot(alice_votes.clone()),
        bob_poll.cast_ballot(bob_votes.clone()),
    );
    r1.expect("Alice cast_ballot");
    r2.expect("Bob cast_ballot");
    println!("✓ Alice and Bob sent their ballots");

    println!("\n--- Alice and Bob receive from all members ---");
    let (r1, r2) = tokio::join!(
        alice_poll.receive_and_apply(),
        bob_poll.receive_and_apply(),
    );
    r1.expect("Alice receive_and_apply");
    r2.expect("Bob receive_and_apply");

    // cast_ballot applies to local state immediately, so Alice's own votes
    // are already present.  receive_and_apply added Bob's ballot.
    alice_poll.poll_state().ballots.get("Alice").expect("Alice ballot in state");

    // Verify Alice's tally
    let alice_tally = alice_poll.tally();
    let mon = alice_tally.iter().find(|t| t.slot.id == "mon-9").expect("mon-9");
    let tue = alice_tally.iter().find(|t| t.slot.id == "tue-9").expect("tue-9");
    // Alice=Yes, Bob=No
    assert_eq!(mon.yes,   1, "mon-9 yes");
    assert_eq!(mon.no,    1, "mon-9 no");
    assert_eq!(mon.maybe, 0, "mon-9 maybe");
    // Alice=Maybe, Bob=Yes
    assert_eq!(tue.yes,   1, "tue-9 yes");
    assert_eq!(tue.no,    0, "tue-9 no");
    assert_eq!(tue.maybe, 1, "tue-9 maybe");
    println!("✓ Alice's tally: mon-9 Yes={} No={} Maybe={}", mon.yes, mon.no, mon.maybe);
    println!("✓ Alice's tally: tue-9 Yes={} No={} Maybe={}", tue.yes, tue.no, tue.maybe);

    println!("\n✅ Two-voter tally test passed!");
}

// ---------------------------------------------------------------------------
// Test 2: three voters, unanimous best slot
// ---------------------------------------------------------------------------

/// Alice, Bob, and Carol each vote.  All three agree on Wednesday, so
/// `best_slot()` should return Wednesday for every participant.
#[tokio::test]
async fn test_tally_three_voters() {
    println!("\n=== Test: Tally poll with three voters ===");

    let (alice_thin, bob_thin, carol_thin) = tokio::join!(
        setup_client("alice"),
        setup_client("bob"),
        setup_client("carol"),
    );
    let alice_thin = alice_thin.expect("Alice ThinClient");
    let bob_thin   = bob_thin.expect("Bob ThinClient");
    let carol_thin = carol_thin.expect("Carol ThinClient");

    let alice_ph = PigeonholeClient::new_in_memory(alice_thin.clone()).expect("Alice ph");
    let bob_ph   = PigeonholeClient::new_in_memory(bob_thin.clone()).expect("Bob ph");
    let carol_ph = PigeonholeClient::new_in_memory(carol_thin.clone()).expect("Carol ph");

    println!("\n--- Alice creates the poll ---");
    let mut alice_poll = TallyPoll::new_poll(
        &alice_ph, "standup-3v", "Alice",
        "Team standup", three_slots(),
    ).await.expect("Alice new_poll");
    let alice_intro = alice_poll.my_introduction();

    println!("\n--- Bob and Carol join in parallel ---");
    let (bob_poll, carol_poll) = tokio::join!(
        TallyPoll::join_poll(&bob_ph,   "standup-3v", "Bob",   &alice_intro),
        TallyPoll::join_poll(&carol_ph, "standup-3v", "Carol", &alice_intro),
    );
    let mut bob_poll   = bob_poll.expect("Bob join_poll");
    let mut carol_poll = carol_poll.expect("Carol join_poll");

    let bob_intro   = bob_poll.my_introduction();
    let carol_intro = carol_poll.my_introduction();

    println!("\n--- Exchange introductions ---");
    alice_poll.add_member(&alice_ph, &bob_intro).expect("Alice add Bob");
    alice_poll.add_member(&alice_ph, &carol_intro).expect("Alice add Carol");
    // Bob and Carol already have Alice from join_poll.
    bob_poll.add_member(&bob_ph, &carol_intro).expect("Bob add Carol");
    carol_poll.add_member(&carol_ph, &bob_intro).expect("Carol add Bob");

    println!("\n--- Bob and Carol receive Alice's CreatePoll ---");
    // Each of Bob and Carol needs to receive Alice's CreatePoll to learn the slots.
    let (r1, r2) = tokio::join!(
        bob_poll.receive_one_and_apply(),
        carol_poll.receive_one_and_apply(),
    );
    r1.expect("Bob receive CreatePoll");
    r2.expect("Carol receive CreatePoll");
    assert_eq!(bob_poll.poll_state().slots.len(), 3);
    assert_eq!(carol_poll.poll_state().slots.len(), 3);
    println!("✓ Bob and Carol know the 3 slots");

    println!("\n--- All three cast ballots in parallel ---");
    // All three vote Yes on wed-9 (Wednesday).
    let (r1, r2, r3) = tokio::join!(
        alice_poll.cast_ballot(HashMap::from([
            ("mon-9".to_string(), Availability::No),
            ("tue-9".to_string(), Availability::No),
            ("wed-9".to_string(), Availability::Yes),
        ])),
        bob_poll.cast_ballot(HashMap::from([
            ("mon-9".to_string(), Availability::Maybe),
            ("tue-9".to_string(), Availability::No),
            ("wed-9".to_string(), Availability::Yes),
        ])),
        carol_poll.cast_ballot(HashMap::from([
            ("mon-9".to_string(), Availability::No),
            ("tue-9".to_string(), Availability::Maybe),
            ("wed-9".to_string(), Availability::Yes),
        ])),
    );
    r1.expect("Alice cast"); r2.expect("Bob cast"); r3.expect("Carol cast");
    println!("✓ All three cast Yes on Wednesday");

    println!("\n--- All three receive from all members in parallel ---");
    let (r1, r2, r3) = tokio::join!(
        alice_poll.receive_and_apply(),
        bob_poll.receive_and_apply(),
        carol_poll.receive_and_apply(),
    );
    r1.expect("Alice receive"); r2.expect("Bob receive"); r3.expect("Carol receive");

    println!("\n--- Verify best_slot is Wednesday for all three ---");
    for (name, poll) in [("Alice", &alice_poll), ("Bob", &bob_poll), ("Carol", &carol_poll)] {
        let best = poll.best_slot().expect(&format!("{} best_slot is None", name));
        assert_eq!(best.id, "wed-9", "{} best_slot wrong", name);
        println!("✓ {} best_slot: '{}'", name, best.label);
    }

    println!("\n✅ Three-voter tally test passed!");
}

// ---------------------------------------------------------------------------
// Test 3: ballot update (last-write-wins)
// ---------------------------------------------------------------------------

/// Bob first votes No on Monday, then changes his mind and votes Yes.
/// Alice should see only the latest ballot from Bob.
#[tokio::test]
async fn test_tally_ballot_update() {
    println!("\n=== Test: Ballot update (last-write-wins) ===");

    let (alice_thin, bob_thin) = tokio::join!(
        setup_client("alice"),
        setup_client("bob"),
    );
    let alice_thin = alice_thin.expect("Alice ThinClient");
    let bob_thin   = bob_thin.expect("Bob ThinClient");

    let alice_ph = PigeonholeClient::new_in_memory(alice_thin.clone()).expect("Alice ph");
    let bob_ph   = PigeonholeClient::new_in_memory(bob_thin.clone()).expect("Bob ph");

    let mut alice_poll = TallyPoll::new_poll(
        &alice_ph, "standup-upd", "Alice",
        "Update test poll", two_slots(),
    ).await.expect("Alice new_poll");

    let alice_intro = alice_poll.my_introduction();
    let mut bob_poll = TallyPoll::join_poll(
        &bob_ph, "standup-upd", "Bob", &alice_intro,
    ).await.expect("Bob join_poll");

    let bob_intro = bob_poll.my_introduction();
    alice_poll.add_member(&alice_ph, &bob_intro).expect("Alice add Bob");
    // Bob already has Alice from join_poll.

    // Bob receives CreatePoll.
    bob_poll.receive_one_and_apply().await.expect("Bob receive CreatePoll");

    println!("\n--- Bob casts first ballot (No on Monday) ---");
    bob_poll.cast_ballot(HashMap::from([
        ("mon-9".to_string(), Availability::No),
        ("tue-9".to_string(), Availability::Yes),
    ])).await.expect("Bob first ballot");

    // Alice receives Bob's first ballot.
    alice_poll.receive_and_apply().await.expect("Alice receive first ballot");
    let tally = alice_poll.tally();
    let mon = tally.iter().find(|t| t.slot.id == "mon-9").unwrap();
    assert_eq!(mon.no, 1, "Bob's first ballot: No on Monday");
    assert_eq!(mon.yes, 0);
    println!("✓ Alice sees Bob's first ballot: mon-9 No={}", mon.no);

    println!("\n--- Bob changes his mind (Yes on Monday) ---");
    bob_poll.cast_ballot(HashMap::from([
        ("mon-9".to_string(), Availability::Yes),
        ("tue-9".to_string(), Availability::Yes),
    ])).await.expect("Bob second ballot");

    // Alice receives Bob's updated ballot.
    alice_poll.receive_and_apply().await.expect("Alice receive second ballot");
    let tally = alice_poll.tally();
    let mon = tally.iter().find(|t| t.slot.id == "mon-9").unwrap();
    // The updated ballot replaces the old one: only Yes should remain.
    assert_eq!(mon.yes, 1, "Bob's updated ballot: Yes on Monday");
    assert_eq!(mon.no,  0, "Old No vote should be gone");
    println!("✓ Alice sees Bob's updated ballot: mon-9 Yes={} No={}", mon.yes, mon.no);

    println!("\n✅ Ballot update (LWW) test passed!");
}

// ---------------------------------------------------------------------------
// Test 4: best_slot tie-breaking
// ---------------------------------------------------------------------------

/// Two slots each receive one Yes vote.  `best_slot` should return the
/// first one in creation order (tie-break by index).
#[tokio::test]
async fn test_tally_best_slot() {
    println!("\n=== Test: best_slot tie-breaking ===");

    let (alice_thin, bob_thin) = tokio::join!(
        setup_client("alice"),
        setup_client("bob"),
    );
    let alice_thin = alice_thin.expect("Alice ThinClient");
    let bob_thin   = bob_thin.expect("Bob ThinClient");

    let alice_ph = PigeonholeClient::new_in_memory(alice_thin.clone()).expect("Alice ph");
    let bob_ph   = PigeonholeClient::new_in_memory(bob_thin.clone()).expect("Bob ph");

    // Alice votes Yes on Monday; Bob votes Yes on Tuesday.
    // Both slots have exactly 1 Yes; Monday (index 0) should win the tie.
    let mut alice_poll = TallyPoll::new_poll(
        &alice_ph, "standup-tie", "Alice",
        "Tie-break test", two_slots(),
    ).await.expect("Alice new_poll");

    let alice_intro = alice_poll.my_introduction();
    let mut bob_poll = TallyPoll::join_poll(
        &bob_ph, "standup-tie", "Bob", &alice_intro,
    ).await.expect("Bob join_poll");

    let bob_intro = bob_poll.my_introduction();
    alice_poll.add_member(&alice_ph, &bob_intro).expect("Alice add Bob");
    // Bob already has Alice from join_poll.

    bob_poll.receive_one_and_apply().await.expect("Bob receive CreatePoll");

    let (r1, r2) = tokio::join!(
        alice_poll.cast_ballot(HashMap::from([
            ("mon-9".to_string(), Availability::Yes),
            ("tue-9".to_string(), Availability::No),
        ])),
        bob_poll.cast_ballot(HashMap::from([
            ("mon-9".to_string(), Availability::No),
            ("tue-9".to_string(), Availability::Yes),
        ])),
    );
    r1.expect("Alice cast"); r2.expect("Bob cast");

    let (r1, r2) = tokio::join!(
        alice_poll.receive_and_apply(),
        bob_poll.receive_and_apply(),
    );
    r1.expect("Alice receive"); r2.expect("Bob receive");

    // Both slots have 1 Yes; Monday comes first → it wins the tie.
    let best = alice_poll.best_slot().expect("best_slot should exist");
    assert_eq!(best.id, "mon-9", "tie broken by creation order");
    println!("✓ Alice's best_slot: '{}' (tie broken by index)", best.label);

    let best = bob_poll.best_slot().expect("bob best_slot");
    assert_eq!(best.id, "mon-9", "Bob also sees Monday win the tie");
    println!("✓ Bob's best_slot: '{}'", best.label);

    println!("\n✅ best_slot tie-breaking test passed!");
}
