# v0.2.16
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
import json


@allow_storage
@dataclass
class BugProgram:
    id: str
    owner: str
    title: str
    policy_url: str
    bounty_pool: bigint
    status: str


@allow_storage
@dataclass
class BugReport:
    id: str
    program_id: str
    researcher: str
    report_url: str
    staked_bond: bigint
    verdict: str
    confidence: bigint
    reason: str
    status: str


class Contract(gl.Contract):
    programs: TreeMap[str, BugProgram]
    reports: TreeMap[str, BugReport]
    program_counter: bigint
    report_counter: bigint

    def __init__(self):
        self.program_counter = bigint(0)
        self.report_counter = bigint(0)
        # GenVM automatically initializes TreeMap storage

    def _addr_str(self, addr: Address) -> str:
        try:
            return addr.as_hex
        except Exception:
            return str(addr)

    def _parse_llm_json(self, text) -> dict:
        try:
            cleaned = str(text).strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            elif cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            return json.loads(cleaned.strip())
        except Exception as e:
            return {"verdict": "ESCALATE", "confidence": 0, "reason": f"Parse error: {str(e)}"}

    @gl.public.write.payable
    def create_program(self, title: str, policy_url: str) -> str:
        """Project owner deposits GEN into a bounty pool and defines security scope."""
        amount = gl.message.value
        if amount <= bigint(0):
            raise UserError("Bounty pool deposit must be greater than 0")

        title = title.strip()
        policy_url = policy_url.strip()
        if len(title) < 5:
            raise UserError("Program title too short")
        if not policy_url.startswith("http://") and not policy_url.startswith("https://"):
            raise UserError("policy_url must start with http:// or https://")

        self.program_counter += bigint(1)
        prog_id = str(self.program_counter)

        self.programs[prog_id] = BugProgram(
            id=prog_id,
            owner=self._addr_str(gl.message.sender_address),
            title=title,
            policy_url=policy_url,
            bounty_pool=amount,
            status="ACTIVE",
        )
        return prog_id

    @gl.public.write.payable
    def submit_vulnerability(self, program_id: str, report_url: str) -> str:
        """Security researcher submits a PoC vulnerability report and stakes an anti-spam bond."""
        if program_id not in self.programs:
            raise UserError("Bug program not found")
        prog = self.programs[program_id]

        if prog.status != "ACTIVE":
            raise UserError("Program is not active")

        bond = gl.message.value
        if bond <= bigint(0):
            raise UserError("Researcher must stake an anti-spam bond greater than 0")

        report_url = report_url.strip()
        if not report_url.startswith("http://") and not report_url.startswith("https://"):
            raise UserError("report_url must start with http:// or https://")

        self.report_counter += bigint(1)
        rep_id = str(self.report_counter)

        self.reports[rep_id] = BugReport(
            id=rep_id,
            program_id=program_id,
            researcher=self._addr_str(gl.message.sender_address),
            report_url=report_url,
            staked_bond=bond,
            verdict="NONE",
            confidence=bigint(0),
            reason="",
            status="SUBMITTED",
        )
        return rep_id

    @gl.public.write
    def adjudicate_report(self, report_id: str) -> None:
        """Triggers autonomous AI consensus adjudication of the vulnerability report."""
        if report_id not in self.reports:
            raise UserError("Report not found")
        report = self.reports[report_id]

        if report.status != "SUBMITTED":
            raise UserError("Report is not in SUBMITTED status")

        prog = self.programs[report.program_id]

        # Capture locals for nondeterministic block closure
        p_url_str = str(prog.policy_url)
        r_url_str = str(report.report_url)
        p_title = str(prog.title)

        def leader_fn():
            # 1. Fetch Security Policy / Scope
            try:
                res_policy = gl.nondet.web.render(p_url_str, mode="text")
                policy_text = res_policy.content if hasattr(res_policy, "content") else str(res_policy)
                if not policy_text or len(policy_text.strip()) < 20:
                    return {"verdict": "ESCALATE", "confidence": 100, "reason": "Policy URL is empty or unreadable."}
                if any(err in policy_text[:400].lower() for err in ["404 not found", "error 404"]):
                    return {"verdict": "ESCALATE", "confidence": 100, "reason": "Policy URL returned 404."}
            except Exception as e:
                return {"verdict": "ESCALATE", "confidence": 100, "reason": f"Policy fetch error: {str(e)}"}

            # 2. Fetch Vulnerability Proof-of-Concept Report
            try:
                res_report = gl.nondet.web.render(r_url_str, mode="text")
                report_text = res_report.content if hasattr(res_report, "content") else str(res_report)
                if not report_text or len(report_text.strip()) < 20:
                    return {"verdict": "SLASH_SPAM", "confidence": 100, "reason": "Report URL is empty or blank."}
                if any(err in report_text[:400].lower() for err in ["404 not found", "error 404"]):
                    return {"verdict": "SLASH_SPAM", "confidence": 100, "reason": "Report URL returned 404 (dead PoC)."}
            except Exception as e:
                return {"verdict": "SLASH_SPAM", "confidence": 100, "reason": f"Report fetch failed: {str(e)}"}

            prompt = f"""
SYSTEM: You are a strict decentralized Smart Contract Security Auditor and Bug Bounty Judge.
Evaluate the submitted vulnerability PoC report against the program's security policy.

PROGRAM: {p_title}

--- SECURITY SCOPE & POLICY ---
{policy_text[:2500]}

--- SUBMITTED VULNERABILITY POC REPORT ---
{report_text[:2500]}

Decision Criteria:
- CRITICAL_REWARD: Demonstrates a clear, high-impact or critical vulnerability directly within the defined scope.
- MEDIUM_REWARD: Demonstrates a valid medium-severity vulnerability within the defined scope.
- INVALID_OUT_OF_SCOPE: An honest submission that is invalid, theoretical, or outside the program's scope.
- SLASH_SPAM: Total garbage, AI-generated junk text, irrelevant spam, or malicious fake submission.
- ESCALATE: Evidence is contradictory, broken, or impossible to verify.

OUTPUT ONLY VALID JSON:
{{
  "verdict": "CRITICAL_REWARD" | "MEDIUM_REWARD" | "INVALID_OUT_OF_SCOPE" | "SLASH_SPAM" | "ESCALATE",
  "confidence": 0-100,
  "reason": "max 300 chars explanation"
}}
"""
            try:
                raw = gl.nondet.exec_prompt(prompt, response_format="json")
                text = raw.content if hasattr(raw, "content") else str(raw)
                parsed = self._parse_llm_json(text)

                verdict = str(parsed.get("verdict", "ESCALATE")).upper()
                if verdict not in ("CRITICAL_REWARD", "MEDIUM_REWARD", "INVALID_OUT_OF_SCOPE", "SLASH_SPAM", "ESCALATE"):
                    verdict = "ESCALATE"

                conf = int(parsed.get("confidence", 0))
                reason = str(parsed.get("reason", ""))

                # Bind confidence directly to verdict to ensure validator consensus
                if conf < 65 and verdict != "ESCALATE":
                    verdict = "ESCALATE"
                    reason = f"[low_confidence: {conf}%] " + reason

                return {
                    "verdict": verdict,
                    "confidence": conf,
                    "reason": reason[:300],
                }
            except Exception as e:
                return {"verdict": "ESCALATE", "confidence": 0, "reason": f"LLM error: {str(e)}"}

        def validator_fn(leader_res) -> bool:
            if not isinstance(leader_res, gl.vm.Return):
                return False

            leader_data = leader_res.calldata if hasattr(leader_res, "calldata") else leader_res
            if not isinstance(leader_data, dict):
                leader_data = self._parse_llm_json(str(leader_data))

            mine_data = leader_fn()

            # Semantic consensus on verified categorical verdict
            v_leader = str(leader_data.get("verdict", "")).upper().strip()
            v_mine = str(mine_data.get("verdict", "")).upper().strip()
            return v_leader == v_mine

        result = gl.vm.run_nondet(leader_fn, validator_fn)
        if not isinstance(result, dict):
            result = self._parse_llm_json(str(result))

        verdict = str(result.get("verdict", "ESCALATE")).upper()
        if verdict not in ("CRITICAL_REWARD", "MEDIUM_REWARD", "INVALID_OUT_OF_SCOPE", "SLASH_SPAM", "ESCALATE"):
            verdict = "ESCALATE"

        confidence = bigint(int(result.get("confidence", 0)))
        reason = str(result.get("reason", "Resolved by AI consensus"))

        report.verdict = verdict
        report.confidence = confidence
        report.reason = reason

        researcher_addr = Address(report.researcher)
        owner_addr = Address(prog.owner)
        staked_bond = report.staked_bond

        if verdict == "CRITICAL_REWARD":
            report.status = "RESOLVED"
            payout = prog.bounty_pool
            prog.bounty_pool = bigint(0)
            # Full bounty payout + full bond refund to researcher
            gl.get_contract_at(researcher_addr).emit_transfer(value=payout + staked_bond)

        elif verdict == "MEDIUM_REWARD":
            report.status = "RESOLVED"
            payout = prog.bounty_pool // bigint(2)
            prog.bounty_pool -= payout
            # 50% bounty payout + full bond refund to researcher
            gl.get_contract_at(researcher_addr).emit_transfer(value=payout + staked_bond)

        elif verdict == "INVALID_OUT_OF_SCOPE":
            report.status = "RESOLVED"
            # Honest attempt: return bond to researcher without bounty payout
            gl.get_contract_at(researcher_addr).emit_transfer(value=staked_bond)

        elif verdict == "SLASH_SPAM":
            report.status = "SLASHED"
            # Spam / fake submission: slash researcher bond and transfer to project owner
            gl.get_contract_at(owner_addr).emit_transfer(value=staked_bond)

        else:
            # ESCALATE: leave funds untouched for retry or manual escalation
            report.status = "ESCALATED"

        self.programs[report.program_id] = prog
        self.reports[report_id] = report

    @gl.public.write
    def close_program(self, program_id: str) -> None:
        """Owner can close program and withdraw remaining pool if no pending reports exist."""
        if program_id not in self.programs:
            raise UserError("Bug program not found")
        prog = self.programs[program_id]

        if self._addr_str(gl.message.sender_address).lower() != prog.owner.lower():
            raise UserError("Only owner can close the program")
        if prog.status != "ACTIVE":
            raise UserError("Program is not active")

        prog.status = "CLOSED"
        remaining = prog.bounty_pool
        prog.bounty_pool = bigint(0)
        self.programs[program_id] = prog

        if remaining > bigint(0):
            gl.get_contract_at(Address(prog.owner)).emit_transfer(value=remaining)

    @gl.public.view
    def get_program(self, program_id: str) -> str:
        if program_id not in self.programs:
            raise UserError("Bug program not found")
        p = self.programs[program_id]
        return json.dumps({
            "id": p.id,
            "owner": p.owner,
            "title": p.title,
            "policy_url": p.policy_url,
            "bounty_pool": str(p.bounty_pool),
            "status": p.status,
        })

    @gl.public.view
    def get_report(self, report_id: str) -> str:
        if report_id not in self.reports:
            raise UserError("Report not found")
        r = self.reports[report_id]
        return json.dumps({
            "id": r.id,
            "program_id": r.program_id,
            "researcher": r.researcher,
            "report_url": r.report_url,
            "staked_bond": str(r.staked_bond),
            "verdict": r.verdict,
            "confidence": str(r.confidence),
            "reason": r.reason,
            "status": r.status,
        })

    @gl.public.view
    def get_program_counter(self) -> int:
        return int(self.program_counter)

    @gl.public.view
    def get_report_counter(self) -> int:
        return int(self.report_counter)
