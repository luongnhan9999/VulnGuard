import pytest
from gltest import *


@pytest.fixture
def contract(direct_deploy):
    return direct_deploy("contracts/vuln_guard.py")


def test_create_program_success(contract, direct_vm, direct_owner):
    owner = direct_owner
    direct_vm.sender = owner
    direct_vm.value = 10000

    prog_id = contract.create_program(
        "DeFi Vault Security Program",
        "https://example.com/security_policy.txt",
    )

    assert str(prog_id) == "1"
    assert contract.get_program_counter() == 1

    prog_json = contract.get_program("1")
    assert '"id": "1"' in prog_json
    assert '"title": "DeFi Vault Security Program"' in prog_json
    assert '"bounty_pool": "10000"' in prog_json
    assert '"status": "ACTIVE"' in prog_json


def test_create_program_invalid_inputs(contract, direct_vm, direct_owner):
    owner = direct_owner

    # Zero deposit
    direct_vm.sender = owner
    direct_vm.value = 0
    with pytest.raises(Exception):
        contract.create_program(
            "DeFi Vault Security Program",
            "https://example.com/policy.txt",
        )

    # Title too short
    direct_vm.sender = owner
    direct_vm.value = 1000
    with pytest.raises(Exception):
        contract.create_program(
            "Tiny",
            "https://example.com/policy.txt",
        )

    # Invalid URL scheme
    direct_vm.sender = owner
    direct_vm.value = 1000
    with pytest.raises(Exception):
        contract.create_program(
            "DeFi Vault Security Program",
            "ftp://example.com/policy.txt",
        )


def test_submit_vulnerability_success(contract, direct_vm, direct_owner, direct_alice):
    owner = direct_owner
    researcher = direct_alice

    direct_vm.sender = owner
    direct_vm.value = 10000
    prog_id = contract.create_program(
        "DeFi Vault Security Program",
        "https://example.com/security_policy.txt",
    )

    direct_vm.sender = researcher
    direct_vm.value = 500
    report_id = contract.submit_vulnerability(
        prog_id,
        "https://example.com/poc_report.txt",
    )

    assert str(report_id) == "1"
    assert contract.get_report_counter() == 1

    report_json = contract.get_report("1")
    assert '"id": "1"' in report_json
    assert '"program_id": "1"' in report_json
    assert '"staked_bond": "500"' in report_json
    assert '"status": "SUBMITTED"' in report_json
    assert '"verdict": "NONE"' in report_json


def test_submit_vulnerability_invalid(contract, direct_vm, direct_owner, direct_alice):
    owner = direct_owner
    researcher = direct_alice

    direct_vm.sender = owner
    direct_vm.value = 10000
    prog_id = contract.create_program(
        "DeFi Vault Security Program",
        "https://example.com/security_policy.txt",
    )

    # Non-existent program
    direct_vm.sender = researcher
    direct_vm.value = 500
    with pytest.raises(Exception):
        contract.submit_vulnerability(
            "999",
            "https://example.com/poc.txt",
        )

    # Zero bond
    direct_vm.sender = researcher
    direct_vm.value = 0
    with pytest.raises(Exception):
        contract.submit_vulnerability(
            prog_id,
            "https://example.com/poc.txt",
        )

    # Invalid report URL
    direct_vm.sender = researcher
    direct_vm.value = 500
    with pytest.raises(Exception):
        contract.submit_vulnerability(
            prog_id,
            "invalid-url",
        )


def test_close_program(contract, direct_vm, direct_owner, direct_alice):
    owner = direct_owner
    other = direct_alice

    direct_vm.sender = owner
    direct_vm.value = 10000
    prog_id = contract.create_program(
        "DeFi Vault Security Program",
        "https://example.com/security_policy.txt",
    )

    # Non-owner cannot close
    direct_vm.sender = other
    direct_vm.value = 0
    with pytest.raises(Exception):
        contract.close_program(prog_id)

    # Owner closes program
    direct_vm.sender = owner
    direct_vm.value = 0
    contract.close_program(prog_id)

    prog_json = contract.get_program(prog_id)
    assert '"status": "CLOSED"' in prog_json
    assert '"bounty_pool": "0"' in prog_json

    # Cannot submit to closed program
    direct_vm.sender = other
    direct_vm.value = 500
    with pytest.raises(Exception):
        contract.submit_vulnerability(
            prog_id,
            "https://example.com/poc.txt",
        )
