import pytest
from genlayer.testing import *


@pytest.fixture
def contract(deploy_contract):
    return deploy_contract("contracts/vuln_guard.py")


def test_create_program_success(contract, accounts):
    owner = accounts[0]

    prog_id = contract.create_program(
        "DeFi Vault Security Program",
        "https://example.com/security_policy.txt",
        sender=owner,
        value=10000
    )

    assert prog_id == "1"
    assert contract.get_program_counter() == 1

    prog_json = contract.get_program("1")
    assert '"id": "1"' in prog_json
    assert '"title": "DeFi Vault Security Program"' in prog_json
    assert '"bounty_pool": "10000"' in prog_json
    assert '"status": "ACTIVE"' in prog_json


def test_create_program_invalid_inputs(contract, accounts):
    owner = accounts[0]

    # Zero deposit
    with pytest.raises(Exception, match="Bounty pool deposit must be greater than 0"):
        contract.create_program(
            "DeFi Vault Security Program",
            "https://example.com/policy.txt",
            sender=owner,
            value=0
        )

    # Title too short
    with pytest.raises(Exception, match="Program title too short"):
        contract.create_program(
            "Tiny",
            "https://example.com/policy.txt",
            sender=owner,
            value=1000
        )

    # Invalid URL scheme
    with pytest.raises(Exception, match="policy_url must start with http:// or https://"):
        contract.create_program(
            "DeFi Vault Security Program",
            "ftp://example.com/policy.txt",
            sender=owner,
            value=1000
        )


def test_submit_vulnerability_success(contract, accounts):
    owner = accounts[0]
    researcher = accounts[1]

    prog_id = contract.create_program(
        "DeFi Vault Security Program",
        "https://example.com/security_policy.txt",
        sender=owner,
        value=10000
    )

    report_id = contract.submit_vulnerability(
        prog_id,
        "https://example.com/poc_report.txt",
        sender=researcher,
        value=500
    )

    assert report_id == "1"
    assert contract.get_report_counter() == 1

    report_json = contract.get_report("1")
    assert '"id": "1"' in report_json
    assert '"program_id": "1"' in report_json
    assert '"staked_bond": "500"' in report_json
    assert '"status": "SUBMITTED"' in report_json
    assert '"verdict": "NONE"' in report_json


def test_submit_vulnerability_invalid(contract, accounts):
    owner = accounts[0]
    researcher = accounts[1]

    prog_id = contract.create_program(
        "DeFi Vault Security Program",
        "https://example.com/security_policy.txt",
        sender=owner,
        value=10000
    )

    # Non-existent program
    with pytest.raises(Exception, match="Bug program not found"):
        contract.submit_vulnerability(
            "999",
            "https://example.com/poc.txt",
            sender=researcher,
            value=500
        )

    # Zero bond
    with pytest.raises(Exception, match="Researcher must stake an anti-spam bond greater than 0"):
        contract.submit_vulnerability(
            prog_id,
            "https://example.com/poc.txt",
            sender=researcher,
            value=0
        )

    # Invalid report URL
    with pytest.raises(Exception, match="report_url must start with http:// or https://"):
        contract.submit_vulnerability(
            prog_id,
            "invalid-url",
            sender=researcher,
            value=500
        )


def test_close_program(contract, accounts):
    owner = accounts[0]
    other = accounts[1]

    prog_id = contract.create_program(
        "DeFi Vault Security Program",
        "https://example.com/security_policy.txt",
        sender=owner,
        value=10000
    )

    # Non-owner cannot close
    with pytest.raises(Exception, match="Only owner can close the program"):
        contract.close_program(prog_id, sender=other)

    # Owner closes program
    contract.close_program(prog_id, sender=owner)

    prog_json = contract.get_program(prog_id)
    assert '"status": "CLOSED"' in prog_json
    assert '"bounty_pool": "0"' in prog_json

    # Cannot submit to closed program
    with pytest.raises(Exception, match="Program is not active"):
        contract.submit_vulnerability(
            prog_id,
            "https://example.com/poc.txt",
            sender=other,
            value=500
        )
