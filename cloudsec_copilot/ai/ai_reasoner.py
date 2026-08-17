from __future__ import annotations

import json
import os
from typing import Any, Dict
from urllib import error, request

from dotenv import load_dotenv

load_dotenv()


class AIReasoner:
    """Generates structured risk explanation, business impact, and safe remediation guidance.

    Priority order:
    1. OpenRouter API (hosted)
    2. Hugging Face Inference API (hosted)
    3. Local Ollama server
    4. Deterministic fallback explanation
    """

    def _call_openrouter(self, prompt: str) -> str | None:
        token = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENROUTER_KEY")
        model = os.getenv("OPENROUTER_MODEL") or os.getenv("OR_MODEL") or "openai/gpt-4o-mini"
        if not token:
            return None

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 250,
        }

        try:
            req = request.Request(
                "https://openrouter.ai/api/v1/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                    "HTTP-Referer": "https://localhost",
                    "X-Title": "CloudSec-Copilot",
                },
                method="POST",
            )
            with request.urlopen(req, timeout=25) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                choices = body.get("choices") or []
                if not choices:
                    return None
                message = choices[0].get("message", {})
                content = message.get("content")
                if isinstance(content, list):
                    text_parts = []
                    for part in content:
                        if isinstance(part, dict):
                            text_parts.append(part.get("text") or part.get("content") or "")
                    content = "\n".join(filter(None, text_parts))
                return (content or "").strip() or None
        except (error.URLError, TimeoutError, ValueError, OSError):
            return None

    def _call_huggingface(self, prompt: str) -> str | None:
        token = os.getenv("HF_API_TOKEN") or os.getenv("HUGGINGFACE_API_TOKEN")
        model = os.getenv("HF_MODEL") or os.getenv("HUGGINGFACE_MODEL") or "mistralai/Mistral-7B-Instruct-v0.2"
        if not token:
            return None

        base_url = os.getenv("HF_BASE_URL", "https://api-inference.huggingface.co")
        payload = {
            "inputs": prompt,
            "parameters": {"max_new_tokens": 250, "temperature": 0.1},
            "options": {"wait_for_model": True},
        }

        try:
            req = request.Request(
                f"{base_url}/models/{model}",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                method="POST",
            )
            with request.urlopen(req, timeout=20) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                if isinstance(body, list) and body and isinstance(body[0], dict):
                    return body[0].get("generated_text", "").strip() or None
                if isinstance(body, dict):
                    if "generated_text" in body:
                        return body["generated_text"].strip() or None
                    if "error" in body:
                        return None
                return None
        except (error.URLError, TimeoutError, ValueError, OSError):
            return None

    def _call_ollama(self, prompt: str) -> str | None:
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "llama3.2")
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1},
        }

        try:
            req = request.Request(
                f"{base_url}/api/generate",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "").strip() or None
        except (error.URLError, TimeoutError, ValueError, OSError):
            return None

    def reason(self, finding: Dict[str, Any], score: float, graph_summary: Dict[str, Any]) -> Dict[str, Any]:
        resource = finding.get("resource_id", "unknown-resource")
        title = finding.get("title", "Unspecified cloud finding")
        prompt = (
            f"Explain a cloud security issue in concise but practical terms. "
            f"Issue: {title}. Resource: {resource}. Risk score: {score:.1f}/10. "
            f"Graph summary: {graph_summary}. Give me: 1) a succinct summary 2) business impact 3) steps to remediate 4) a rollback plan."
        )

        model_response = self._call_openrouter(prompt) or self._call_huggingface(prompt) or self._call_ollama(prompt)
        if model_response:
            return {
                "summary": model_response.split("\n")[0][:220] or f"{title} on {resource} requires immediate review.",
                "impact": "The issue is evaluated through the live dependency graph and could expose connected cloud assets to misuse or data exposure.",
                "steps": [
                    "Review the exact resource and network exposure in the live environment.",
                    "Apply the least-privilege fix suggested by the model and documented resource policy.",
                    "Re-scan the environment to verify the state is secure.",
                ],
                "aws_cli": [
                    f"aws --endpoint-url http://localhost:4566 configure list",
                    "aws --endpoint-url http://localhost:4566 iam list-roles --output table",
                ],
                "rollback": [
                    "Capture the original configuration before remediation.",
                    "Reapply the previous policy or ACL if the change disrupts service access.",
                ],
            }

        summary = (
            f"{title} on {resource} is exposed in the live cloud context and has a graph-driven blast radius. "
            f"The current risk score is {score:.1f}/10 and the dependency path includes {graph_summary.get('entry_points', ['unknown'])}."
        )

        impact = (
            "This misconfiguration can allow public access, privilege abuse, or lateral movement across connected assets. "
            "The exposure can cascade through IAM, storage, and database resources depending on the graph context."
        )

        steps = [
            "Confirm the resource is intentionally exposed and identify the owning team.",
            "Restrict public exposure to a trusted CIDR or private network boundary.",
            "Remove or reduce unnecessary privileges associated with the resource.",
            "Validate the change with a fresh security scan before closing the finding.",
        ]

        aws_cli = [
            f"aws --endpoint-url http://localhost:4566 s3api put-public-access-block --bucket {resource} --public-access-block Configuration='{{\"BlockPublicAcls\":true,\"IgnorePublicAcls\":true,\"BlockPublicPolicy\":true,\"RestrictPublicBuckets\":true}}'",
            "aws --endpoint-url http://localhost:4566 ec2 revoke-security-group-ingress --group-id sg-example --protocol tcp --port 22 --cidr 0.0.0.0/0",
        ]

        rollback = [
            "Capture the original ACL, policy, and ingress configuration before modification.",
            "Reapply the backup configuration if the change causes service interruption.",
        ]

        return {
            "summary": summary,
            "impact": impact,
            "steps": steps,
            "aws_cli": aws_cli,
            "rollback": rollback,
        }
