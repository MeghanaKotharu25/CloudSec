"""
CloudSec-Copilot Final Review Presentation Generator
Generates a highly-polished, 23-slide, 16:9 editable PowerPoint presentation (.pptx)
covering every single component of the CloudSec-Copilot system.
"""

import os
from pathlib import Path
import pptx
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

OUTPUT_FILE = "CloudSec_Final_Review_Presentation.pptx"
IMAGE_PATH = "attack_graph.png"

# Color Palette Constants (High-contrast Modern Dark Tech Aesthetic)
COLOR_BG_DARK = RGBColor(11, 19, 43)          # #0B132B Deep Slate Navy
COLOR_CARD_BG = RGBColor(23, 37, 66)          # #172542 Card Container
COLOR_CARD_BORDER = RGBColor(46, 68, 107)     # #2E446B Subtle Blue Border
COLOR_ACCENT_BLUE = RGBColor(0, 180, 255)     # #00B4FF Cyber Blue
COLOR_ACCENT_CYAN = RGBColor(77, 208, 225)    # #4DD0E1 Bright Cyan
COLOR_ACCENT_GREEN = RGBColor(48, 209, 88)    # #30D158 Verified / Secure
COLOR_ACCENT_RED = RGBColor(255, 69, 58)      # #FF453A Critical Risk
COLOR_ACCENT_ORANGE = RGBColor(255, 159, 10)  # #FF9F0A High Risk / Warning
COLOR_ACCENT_PURPLE = RGBColor(191, 90, 242)  # #BF5AF2 AI Reasoning
COLOR_TEXT_WHITE = RGBColor(255, 255, 255)    # #FFFFFF Primary Text
COLOR_TEXT_MUTED = RGBColor(165, 180, 207)    # #A5B4CF Secondary Muted Text
COLOR_CODE_BG = RGBColor(13, 17, 23)          # Terminal Black
COLOR_CODE_TEXT = RGBColor(126, 231, 135)     # Terminal Green

def create_presentation():
    prs = pptx.Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5)
        )
        bg.fill.solid()
        bg.fill.fore_color.rgb = COLOR_BG_DARK
        bg.line.fill.background()
        return bg

    def add_header(slide, tag, title, subtitle=None):
        # Top Category Tag Badge
        tag_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.5), Inches(0.35))
        tf_tag = tag_box.text_frame
        tf_tag.word_wrap = True
        tf_tag.margin_left = tf_tag.margin_top = tf_tag.margin_right = tf_tag.margin_bottom = 0
        p_tag = tf_tag.paragraphs[0]
        p_tag.text = tag.upper()
        p_tag.font.name = "Calibri"
        p_tag.font.size = Pt(11)
        p_tag.font.bold = True
        p_tag.font.color.rgb = COLOR_ACCENT_CYAN

        # Main Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.72), Inches(11.7), Inches(0.65))
        tf_title = title_box.text_frame
        tf_title.word_wrap = True
        tf_title.margin_left = tf_title.margin_top = tf_title.margin_right = tf_title.margin_bottom = 0
        p_title = tf_title.paragraphs[0]
        p_title.text = title
        p_title.font.name = "Calibri"
        p_title.font.size = Pt(24)
        p_title.font.bold = True
        p_title.font.color.rgb = COLOR_TEXT_WHITE

        # Subtitle / Context (if present)
        if subtitle:
            sub_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.35), Inches(11.7), Inches(0.4))
            tf_sub = sub_box.text_frame
            tf_sub.word_wrap = True
            tf_sub.margin_left = tf_sub.margin_top = tf_sub.margin_right = tf_sub.margin_bottom = 0
            p_sub = tf_sub.paragraphs[0]
            p_sub.text = subtitle
            p_sub.font.name = "Calibri"
            p_sub.font.size = Pt(13)
            p_sub.font.color.rgb = COLOR_TEXT_MUTED

        # Bottom subtle footer
        footer_box = slide.shapes.add_textbox(Inches(0.8), Inches(7.05), Inches(11.7), Inches(0.3))
        tf_foot = footer_box.text_frame
        tf_foot.margin_left = tf_foot.margin_top = tf_foot.margin_right = tf_foot.margin_bottom = 0
        p_foot = tf_foot.paragraphs[0]
        p_foot.text = "CLOUDSEC-COPILOT  |  22AIE305 Introduction to Cloud Computing  |  Final Project Review"
        p_foot.font.name = "Calibri"
        p_foot.font.size = Pt(9)
        p_foot.font.color.rgb = COLOR_TEXT_MUTED

    def add_card(slide, left, top, width, height, bg_color=COLOR_CARD_BG, border_color=COLOR_CARD_BORDER):
        card = slide.shapes.add_shape(
            MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height
        )
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        if border_color:
            card.line.color.rgb = border_color
            card.line.width = Pt(1.5)
        else:
            card.line.fill.background()
        return card

    def add_notes(slide, notes_text):
        notes_slide = slide.notes_slide
        tf = notes_slide.notes_text_frame
        tf.text = notes_text.strip()

    # ==========================================
    # SLIDE 1: TITLE SLIDE
    # ==========================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Decorative accent card
    add_card(s1, Inches(1.0), Inches(1.0), Inches(11.333), Inches(5.5), COLOR_CARD_BG, COLOR_ACCENT_BLUE)

    tbox = s1.shapes.add_textbox(Inches(1.5), Inches(1.4), Inches(10.333), Inches(4.7))
    tf1 = tbox.text_frame
    tf1.word_wrap = True

    p0 = tf1.paragraphs[0]
    p0.text = "22AIE305 - INTRODUCTION TO CLOUD COMPUTING  |  FINAL PROJECT DEFENSE"
    p0.font.name = "Calibri"
    p0.font.size = Pt(13)
    p0.font.bold = True
    p0.font.color.rgb = COLOR_ACCENT_CYAN
    p0.space_after = Pt(14)

    p1 = tf1.add_paragraph()
    p1.text = "CLOUDSEC-COPILOT"
    p1.font.name = "Calibri"
    p1.font.size = Pt(40)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_TEXT_WHITE
    p1.space_after = Pt(8)

    p2 = tf1.add_paragraph()
    p2.text = "Intelligent Cloud Security Posture Management with Attack Graph Reasoning, Guardrailed AI, & Verified Closed-Loop Remediation"
    p2.font.name = "Calibri"
    p2.font.size = Pt(16)
    p2.font.color.rgb = COLOR_TEXT_MUTED
    p2.space_after = Pt(28)

    p3 = tf1.add_paragraph()
    p3.text = "TEAM C2 MEMBERS & REGISTER NUMBERS:"
    p3.font.name = "Calibri"
    p3.font.size = Pt(12)
    p3.font.bold = True
    p3.font.color.rgb = COLOR_ACCENT_BLUE
    p3.space_after = Pt(6)

    team_members = [
        "• CB.SC.U4AIE24220",
        "• CB.SC.U4AIE24232",
        "• CB.SC.U4AIE24241",
        "• CB.SC.U4AIE24264"
    ]
    for mem in team_members:
        pm = tf1.add_paragraph()
        pm.text = mem
        pm.font.name = "Calibri"
        pm.font.size = Pt(12)
        pm.font.color.rgb = COLOR_TEXT_WHITE
        pm.space_after = Pt(3)

    p_git = tf1.add_paragraph()
    p_git.text = "\nGitHub Repository: https://github.com/MeghanaKotharu25/CloudSec"
    p_git.font.name = "Calibri"
    p_git.font.size = Pt(11)
    p_git.font.color.rgb = COLOR_ACCENT_CYAN

    add_notes(s1, """
Good morning respected evaluators. Today, Team C2 presents CloudSec-Copilot for our final review in 22AIE305 Introduction to Cloud Computing.
CloudSec-Copilot is an autonomous yet human-governed cloud security assistant designed to eliminate the critical gap between finding cloud vulnerabilities and safely fixing them.
Our complete codebase, test suite, and infrastructure scripts are fully implemented, verified, and available on GitHub.
    """)

    # ==========================================
    # SLIDE 2: EXECUTIVE SUMMARY & MOTIVATION
    # ==========================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "Executive Overview", "Closing the Cloud Security Gap: From Alerts to Verified Action", "A developer-first, closed-loop Cloud Security Posture Management (CSPM) and remediation assistant")

    # 3 Stat Cards across top
    stats = [
        ("10 CORE MODULES", "Discovery, Graph, Risk, AI Reasoner, Safety Validator, Executor, Rollback, Verifier, Audit, CLI", COLOR_ACCENT_BLUE),
        ("100 PASSING TESTS", "Automated coverage across Unit, Graph Integration, Extended Vulns, Remediation, and live LocalStack pipelines", COLOR_ACCENT_GREEN),
        ("ZERO CLOUD COST", "Emulated local AWS environment powered by LocalStack & Docker for safe reproducible evaluation", COLOR_ACCENT_CYAN),
    ]
    for i, (title, desc, col) in enumerate(stats):
        cx = Inches(0.8 + i * 4.0)
        card = add_card(s2, cx, Inches(1.8), Inches(3.7), Inches(1.6))
        tb = s2.shapes.add_textbox(cx + Inches(0.2), Inches(1.95), Inches(3.3), Inches(1.3))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(16)
        p.font.bold = True
        p.font.color.rgb = col
        p.space_after = Pt(4)
        p2 = tf.add_paragraph()
        p2.text = desc
        p2.font.size = Pt(11)
        p2.font.color.rgb = COLOR_TEXT_MUTED

    # Bottom 2 Comparison Cards
    c_left = add_card(s2, Inches(0.8), Inches(3.6), Inches(5.7), Inches(3.2))
    tb_l = s2.shapes.add_textbox(Inches(1.0), Inches(3.8), Inches(5.3), Inches(2.8))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "THE STATUS QUO (BROKEN WORKFLOW)"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_RED
    p.space_after = Pt(8)
    points_l = [
        "Alert Fatigue: Scanners flood teams with hundreds of isolated alerts lacking contextual relevance.",
        "Disconnected Toxic Combos: Fails to see that an innocent open port connects to an Admin IAM role.",
        "Manual Remediation Void: Developers must manually write error-prone CLI commands or Terraform edits.",
        "Fear of Breaking Production: Lack of safe dry-runs and automated rollbacks prevents teams from acting."
    ]
    for pt in points_l:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(4)

    c_right = add_card(s2, Inches(6.8), Inches(3.6), Inches(5.7), Inches(3.2))
    tb_r = s2.shapes.add_textbox(Inches(7.0), Inches(3.8), Inches(5.3), Inches(2.8))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "OUR SOLUTION (CLOUDSEC-COPILOT)"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_GREEN
    p.space_after = Pt(8)
    points_r = [
        "Attack Graph Intelligence: NetworkX models multi-hop traversal from public internet to crown jewels.",
        "Contextual Risk Scoring: Ranks vulnerabilities by blast radius and lateral movement potential (0-10 scale).",
        "Guardrailed AI Reasoning: OpenRouter LLM explains root causes; AI Safety Validator blocks destructive commands.",
        "Safe Closed-Loop Remediation: Real Boto3 remediation, immutable audit logs, instant rollback, and delta verification."
    ]
    for pt in points_r:
        p = tf_r.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(4)

    add_notes(s2, """
In this slide, we summarize the motivation behind CloudSec-Copilot.
Most cloud security scanners today stop at detection—generating hundreds of alerts that leave developers overwhelmed.
Furthermore, traditional scanners evaluate each resource in isolation, completely missing 'toxic combinations' where an open security group, an attached EC2 instance, and an Admin IAM role form a lethal attack path.
CloudSec-Copilot bridges this gap by unifying discovery, graph modeling, AI reasoning, safety guardrails, automated execution, reversible rollback, and post-remediation verification in a single closed-loop architecture.
    """)

    # ==========================================
    # SLIDE 3: PROBLEM STATEMENT
    # ==========================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "Problem Statement", "The Modern Cloud Security Dilemma: High Velocity, Low Assurance", "Why isolated rule-checking fails in interconnected microservice architectures")

    cards_data = [
        ("1. Heterogeneous Cloud Surfaces", "Modern architectures combine IAM roles, S3 buckets, EC2 compute, Security Groups, SQS queues, and RDS databases. Each service emits fragmented metadata formats, making unified security analysis challenging.", COLOR_ACCENT_BLUE),
        ("2. Hidden Lateral Movement & Toxic Combos", "A low-severity open port on an EC2 instance becomes catastrophic when that instance has an attached IAM role with AdministratorAccess and access to a customer S3 bucket. Single-resource scanners miss this entirely.", COLOR_ACCENT_ORANGE),
        ("3. The 'Detection-Only' Bottleneck", "Security platforms notify developers that a vulnerability exists, but leave remediation entirely manual. DevSecOps engineers spend hours understanding the impact and drafting AWS CLI or Terraform fixes.", COLOR_ACCENT_RED),
        ("4. Reversibility & Autonomous Agent Risks", "Autonomous agents executing cloud fixes can hallucinate destructive actions (like dropping buckets or terminating instances). Without strict safety guardrails and instant rollback mechanisms, automation cannot be trusted in production.", COLOR_ACCENT_PURPLE),
    ]

    for i, (head, text, col) in enumerate(cards_data):
        row = i // 2
        col_idx = i % 2
        left = Inches(0.8 + col_idx * 6.0)
        top = Inches(1.8 + row * 2.5)
        add_card(s3, left, top, Inches(5.7), Inches(2.2))
        tb = s3.shapes.add_textbox(left + Inches(0.2), top + Inches(0.2), Inches(5.3), Inches(1.8))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = head
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = col
        p.space_after = Pt(6)
        p2 = tf.add_paragraph()
        p2.text = text
        p2.font.size = Pt(11)
        p2.font.color.rgb = COLOR_TEXT_WHITE

    add_notes(s3, """
Our problem statement addresses four acute challenges in modern cloud security:
First, cloud assets are diverse and fragmented.
Second, vulnerabilities do not exist in a vacuum; attackers leverage graph paths to pivot across resources.
Third, finding a vulnerability is easy, but remediation is slow, manual, and error-prone.
Fourth, giving AI agents unconstrained access to cloud APIs is dangerous—recent Microsoft research has shown that autonomous agents can destroy assets without validation guardrails.
    """)

    # ==========================================
    # SLIDE 4: PROJECT OBJECTIVES & SCOPE
    # ==========================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "Project Objectives", "Concrete Engineering Goals & Scope of Work", "Defining our primary mission and five specific architectural deliverables")

    # Primary Objective Card
    add_card(s4, Inches(0.8), Inches(1.8), Inches(11.7), Inches(1.2), COLOR_CARD_BG, COLOR_ACCENT_BLUE)
    tb_p = s4.shapes.add_textbox(Inches(1.0), Inches(1.9), Inches(11.3), Inches(1.0))
    tf_p = tb_p.text_frame
    tf_p.word_wrap = True
    p = tf_p.paragraphs[0]
    p.text = "PRIMARY OBJECTIVE:"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_CYAN
    p2 = tf_p.add_paragraph()
    p2.text = "To develop an intelligent, CLI-based cloud security copilot capable of autonomously discovering multi-service cloud infrastructure, detecting misconfigurations, modeling attack dependency graphs, generating AI-guided remediation plans with safety guardrails, executing verified Boto3 fixes, and supporting 100% reversible rollback."
    p2.font.size = Pt(12)
    p2.font.color.rgb = COLOR_TEXT_WHITE

    # 5 Specific Objectives
    spec_objs = [
        ("1. Multi-Service Cloud Discovery", "Collect live inventory from S3, IAM, EC2, SG, SQS, and RDS using Boto3; normalize into strict Pydantic schemas."),
        ("2. Attack Graph & Blast Radius", "Construct directed NetworkX multigraphs to map lateral movement, identify crown jewels, and compute graph blast radius."),
        ("3. Contextual Risk Prioritization", "Formulate a multi-factor mathematical scoring model (0-10) blending rule severity, internet exposure, and reachability."),
        ("4. Guardrailed AI Reasoning", "Integrate OpenRouter LLMs for impact analysis; enforce pre-execution safety filters to block destructive cloud commands."),
        ("5. Closed-Loop Fix, Rollback & Verification", "Execute approved Boto3 fixes, store immutable audit trails, provide one-command rollback, and verify resolution via delta scans.")
    ]

    for i, (title, desc) in enumerate(spec_objs):
        top_pos = Inches(3.2 + i * 0.72)
        add_card(s4, Inches(0.8), top_pos, Inches(11.7), Inches(0.62))
        tb = s4.shapes.add_textbox(Inches(1.0), top_pos + Inches(0.08), Inches(11.3), Inches(0.5))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title + "  —  "
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = COLOR_ACCENT_GREEN
        run = p.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = COLOR_TEXT_WHITE

    add_notes(s4, """
Our project objectives were broken down into five measurable engineering milestones.
From multi-service cloud discovery to attack graph modeling, risk prioritization, AI reasoning with safety validation, and finally verified execution and rollback.
Every single objective listed here was completed and backed by automated integration tests.
    """)

    # ==========================================
    # SLIDE 5: LITERATURE REVIEW & COMPETITIVE MATRIX
    # ==========================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "Literature & Industry Benchmark", "Comparative Analysis with Existing Tools and Research", "Positioning CloudSec-Copilot against enterprise CSPMs, IaC scanners, and academic frameworks")

    # Table
    table_shape = s5.shapes.add_table(6, 5, Inches(0.8), Inches(1.8), Inches(11.7), Inches(4.8))
    table = table_shape.table
    table.columns[0].width = Inches(2.2)
    table.columns[1].width = Inches(1.6)
    table.columns[2].width = Inches(2.5)
    table.columns[3].width = Inches(2.5)
    table.columns[4].width = Inches(2.9)

    headers = ["Platform / Study", "Category / Year", "Key Merits", "Identified Limitations", "CloudSec-Copilot Advantage"]
    for c_idx, h_text in enumerate(headers):
        cell = table.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = COLOR_CARD_BG
        p = cell.text_frame.paragraphs[0]
        p.text = h_text
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = COLOR_ACCENT_CYAN

    rows_data = [
        ("Prowler Cloud Security", "Open-Source CSPM (2026)", "Broad AWS compliance auditing across CIS benchmarks.", "Detection-only; no attack graphs, AI reasoning, or automated fixes.", "Adds attack graph reasoning, OpenRouter AI explanations, and verified Boto3 fixes."),
        ("Checkov (Palo Alto)", "IaC Security (2026)", "Industry standard shift-left scanner for Terraform & K8s.", "Static analysis prior to deploy; blind to live cloud state.", "Operates on deployed runtime cloud infrastructure and live API states."),
        ("Wiz / Orca Security", "Enterprise CSPM (2026)", "Graph-based correlation of IAM, compute, and data assets.", "Commercial, proprietary, expensive closed-source enterprise systems.", "Transparent, open-source, reproducible attack graph with LocalStack emulation."),
        ("TerraRepair / InfraFix", "Academic Research (2025-26)", "Tool-grounded LLM agents repairing Terraform scripts.", "Constrained to IaC code; cannot remediate running cloud assets.", "Directly remediates live cloud resources with Boto3 and verifies state delta."),
        ("AI Agent Security Risks (MS Research, 2026)", "Agent Safety Paper (2026)", "Highlights privilege escalation & unsafe agent actions.", "Shows that unvalidated agents perform destructive actions.", "Introduces AISafetyValidator guardrails: pre-execution checks and destructive action blocks.")
    ]

    for r_idx, row in enumerate(rows_data):
        for c_idx, val in enumerate(row):
            cell = table.cell(r_idx + 1, c_idx)
            cell.fill.solid()
            cell.fill.fore_color.rgb = COLOR_BG_DARK if (r_idx % 2 == 0) else COLOR_CARD_BG
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.size = Pt(9.5)
            if c_idx == 0:
                p.font.bold = True
                p.font.color.rgb = COLOR_ACCENT_BLUE
            elif c_idx == 4:
                p.font.bold = True
                p.font.color.rgb = COLOR_ACCENT_GREEN
            else:
                p.font.color.rgb = COLOR_TEXT_WHITE

    add_notes(s5, """
We benchmarked CloudSec-Copilot against both industry solutions and cutting-edge academic research:
Existing open-source tools like Prowler detect issues but leave developers stranded without remediation.
Tools like Checkov operate shift-left before deployment, but cannot assess runtime cloud states.
Commercial giants like Wiz and Orca pioneered security graphs, but their mechanisms are proprietary black-boxes.
Furthermore, academic papers like TerraRepair operate only on Terraform code, not live infrastructure.
Finally, we incorporated the findings of Microsoft Research's 2026 paper on AI agent risks by designing strict validation guardrails before allowing any remediation command to execute.
    """)

    # ==========================================
    # SLIDE 6: END-TO-END SYSTEM ARCHITECTURE
    # ==========================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "System Architecture", "High-Level Closed-Loop Architecture", "Data flows through 10 interconnected components from discovery to verified remediation")

    # Flow Steps
    steps = [
        ("1. DISCOVERY", "Boto3 multi-service metadata extraction (S3, EC2, IAM, SG, SQS, RDS).", COLOR_ACCENT_BLUE),
        ("2. DETECTION", "Deterministic rule engine flags 7 core vulnerability types.", COLOR_ACCENT_ORANGE),
        ("3. GRAPH ENGINE", "NetworkX builds multi-hop attack paths and calculates blast radius.", COLOR_ACCENT_BLUE),
        ("4. RISK PRIORITIZATION", "Mathematical formula ranks vulnerabilities by severity and reachability.", COLOR_ACCENT_RED),
        ("5. AI REASONER", "OpenRouter LLM interprets graph paths and generates remediation actions.", COLOR_ACCENT_PURPLE),
        ("6. SAFETY VALIDATOR", "Pre-execution guardrails reject destructive actions & validate schemas.", COLOR_ACCENT_ORANGE),
        ("7. EXECUTOR", "Applies approved Boto3 fixes with state snapshotting & HITL approval.", COLOR_ACCENT_GREEN),
        ("8. AUDIT & ROLLBACK", "Immutable audit_log.json enables 100% reversible state restoration.", COLOR_ACCENT_BLUE),
        ("9. VERIFIER", "Post-remediation delta scan proves vulnerability resolution or rollback state.", COLOR_ACCENT_GREEN),
    ]

    for i, (title, desc, col) in enumerate(steps):
        row = i // 3
        col_idx = i % 3
        left = Inches(0.8 + col_idx * 4.0)
        top = Inches(1.8 + row * 1.65)
        add_card(s6, left, top, Inches(3.7), Inches(1.45), COLOR_CARD_BG, col)
        tb = s6.shapes.add_textbox(left + Inches(0.15), top + Inches(0.15), Inches(3.4), Inches(1.15))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(12)
        p.font.bold = True
        p.font.color.rgb = col
        p.space_after = Pt(4)
        p2 = tf.add_paragraph()
        p2.text = desc
        p2.font.size = Pt(10)
        p2.font.color.rgb = COLOR_TEXT_WHITE

    add_notes(s6, """
This slide presents our complete end-to-end architecture.
Notice that the pipeline forms an unbroken closed loop:
Cloud resources are discovered and scanned; findings are mapped into our NetworkX attack graph; risk scores are calculated; our AI reasoner explains the findings; our safety validator screens the proposed remediation; the executor modifies the cloud state while snapshotting previous configurations; and the verifier re-scans the environment to mathematically confirm that the vulnerability is gone.
    """)

    # ==========================================
    # SLIDE 7: COMPONENT 1 — DISCOVERY ENGINE
    # ==========================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "Component Deep Dive 01", "Cloud Discovery Engine & Normalized Data Modeling", "cloudsec_copilot/discovery/collector.py & cloudsec_copilot/discovery/models.py")

    add_card(s7, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s7.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "MULTI-SERVICE BOTO3 COLLECTORS"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_BLUE
    p.space_after = Pt(8)
    d_points = [
        "Multi-Service Coverage: Boto3 collectors query S3 (buckets, ACLs, public access block), EC2 (instances, tags), IAM (roles, inline policies, access keys), Security Groups (ingress/egress rules), SQS (queues, policies), and RDS.",
        "Resilient Service Fallback: If an AWS service is unconfigured or unavailable in LocalStack (such as RDS), the collector logs a graceful skip rather than generating synthetic or corrupt findings.",
        "Strict Pydantic Validation: Raw heterogeneous AWS dictionary responses are parsed into typed models (S3BucketInfo, SecurityGroupInfo, IAMRoleInfo, EC2InstanceInfo, SQSQueueInfo).",
        "Deterministic Snapshot Export: Outputs an exportable CloudInventorySnapshot JSON preserving ARNs, IDs, and resource relationships for reproducible auditing."
    ]
    for pt in d_points:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(6)

    # Right Card: Code / Schema Box
    add_card(s7, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9), COLOR_CODE_BG, COLOR_CARD_BORDER)
    tb_r = s7.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "DISCOVERY ARCHITECTURE & CODE"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_CYAN
    p.space_after = Pt(8)
    code_snippet = (
        "class DiscoveryCollector:\n"
        "    def __init__(self, endpoint_url=None):\n"
        "        self.s3 = boto3.client('s3', ...)\n"
        "        self.iam = boto3.client('iam', ...)\n"
        "        self.ec2 = boto3.client('ec2', ...)\n"
        "        self.sqs = boto3.client('sqs', ...)\n\n"
        "    def collect_all(self) -> CloudInventorySnapshot:\n"
        "        return CloudInventorySnapshot(\n"
        "            timestamp=datetime.utcnow().isoformat(),\n"
        "            s3_buckets=self.list_buckets(),\n"
        "            security_groups=self.list_security_groups(),\n"
        "            iam_roles=self.list_iam_roles(),\n"
        "            ec2_instances=self.list_ec2_instances(),\n"
        "            sqs_queues=self.list_sqs_queues(),\n"
        "            rds_instances=self.list_rds_instances()\n"
        "        )"
    )
    p2 = tf_r.add_paragraph()
    p2.text = code_snippet
    p2.font.name = "Consolas"
    p2.font.size = Pt(10)
    p2.font.color.rgb = COLOR_CODE_TEXT

    add_notes(s7, """
Component 1 is the Cloud Discovery Engine.
It uses official Boto3 clients to inspect live AWS or LocalStack endpoints.
Rather than dealing with messy, unpredictable JSON dictionaries, we feed all raw metadata into strongly typed Pydantic models.
This guarantees schema integrity throughout all downstream components and ensures that if a service like RDS is not deployed, the system gracefully handles it without crashing.
    """)

    # ==========================================
    # SLIDE 8: COMPONENT 2 — VULNERABILITY SCANNER
    # ==========================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "Component Deep Dive 02", "Deterministic Vulnerability Detection Engine", "cloudsec_copilot/scanner/scanner.py — Zero-hallucination deterministic security rules")

    # Table of Rules
    table_shape = s8.shapes.add_table(8, 4, Inches(0.8), Inches(1.8), Inches(11.7), Inches(4.8))
    table = table_shape.table
    table.columns[0].width = Inches(2.2)
    table.columns[1].width = Inches(1.5)
    table.columns[2].width = Inches(4.5)
    table.columns[3].width = Inches(3.5)

    headers = ["Rule ID", "Base Severity", "Detection Condition & Misconfiguration", "Targeted Cloud Resource"]
    for c_idx, h_text in enumerate(headers):
        cell = table.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = COLOR_CARD_BG
        p = cell.text_frame.paragraphs[0]
        p.text = h_text
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = COLOR_ACCENT_CYAN

    rules_data = [
        ("RULE-S3-PUBLIC", "CRITICAL", "Public read/write ACL (AllUsers) or BlockPublicAccess disabled.", "AWS S3 Buckets"),
        ("RULE-SG-OPEN", "HIGH", "Ingress rule allows 0.0.0.0/0 on sensitive ports (22, 3389, 80).", "AWS Security Groups"),
        ("RULE-IAM-ADMIN", "CRITICAL", "IAM role/policy attaches unconstrained AdministratorAccess.", "AWS IAM Roles & Policies"),
        ("RULE-IAM-KEYS", "HIGH", "IAM user contains active, long-lived access keys (>90 days).", "AWS IAM User Credentials"),
        ("RULE-SQS-PERMISSIVE", "HIGH", "SQS queue policy grants Principal: * with broad action scope.", "AWS SQS Queues"),
        ("RULE-RDS-PUBLIC", "CRITICAL", "RDS database instance has PubliclyAccessible set to True.", "AWS RDS Relational Databases"),
        ("RULE-S3-UNENCRYPTED", "MEDIUM", "S3 bucket lacks default Server-Side Encryption (KMS / AES256).", "AWS S3 Storage Buckets"),
    ]

    for r_idx, row in enumerate(rules_data):
        for c_idx, val in enumerate(row):
            cell = table.cell(r_idx + 1, c_idx)
            cell.fill.solid()
            cell.fill.fore_color.rgb = COLOR_BG_DARK if (r_idx % 2 == 0) else COLOR_CARD_BG
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.size = Pt(10)
            if c_idx == 0:
                p.font.bold = True
                p.font.color.rgb = COLOR_ACCENT_BLUE
            elif c_idx == 1:
                p.font.bold = True
                p.font.color.rgb = COLOR_ACCENT_RED if val == "CRITICAL" else (COLOR_ACCENT_ORANGE if val == "HIGH" else COLOR_ACCENT_CYAN)
            else:
                p.font.color.rgb = COLOR_TEXT_WHITE

    add_notes(s8, """
Component 2 is the Vulnerability Scanner.
A fundamental design decision in CloudSec-Copilot is that detection is 100% deterministic, NOT outsourced to an LLM.
Relying on LLMs for detection causes hallucinations and missed security flaws.
Instead, our rule engine applies exact, programmatic boolean checks against the normalized cloud snapshot.
We have 7 active rules covering S3 storage, Security Group ingress, IAM admin roles and long-lived keys, SQS messaging policies, and RDS public databases.
    """)

    # ==========================================
    # SLIDE 9: COMPONENT 3 — ATTACK GRAPH ENGINE
    # ==========================================
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "Component Deep Dive 03", "Attack & Infrastructure Dependency Graph Engine", "cloudsec_copilot/graph/graph_builder.py — Modeling lateral movement with NetworkX")

    # Left: Explanation Card
    add_card(s9, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s9.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "GRAPH-BASED LATERAL MOVEMENT MODELING"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_BLUE
    p.space_after = Pt(8)
    g_points = [
        "NetworkX MultiDiGraph: Represents cloud assets as nodes (Internet, Security Groups, EC2, IAM Roles, S3, SQS) and relationships as directed edges.",
        "Edge Semantics: Edges encode directional trust boundaries: EXPOSES_TO_INTERNET, ATTACHED_TO, ASSUMES_ROLE, CAN_READ_WRITE, and PERMITS_INGRESS.",
        "Multi-Hop Attack Path Traversal: Uses shortest-path algorithms to trace paths from external entry points (0.0.0.0/0) to crown jewel data stores.",
        "Blast Radius Calculation: Walks outward from any vulnerable node to compute its reachability score and total reachable asset count.",
        "Artifact Export: Outputs both machine-readable JSON (attack_graph.json) and rendered visualizations (attack_graph.png)."
    ]
    for pt in g_points:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(10.5)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(5)

    # Right: Rendered Graph Image / Card
    add_card(s9, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9), COLOR_CARD_BG, COLOR_ACCENT_CYAN)
    if os.path.exists(IMAGE_PATH):
        try:
            s9.shapes.add_picture(IMAGE_PATH, Inches(7.0), Inches(2.0), width=Inches(5.3))
        except Exception:
            tb_img = s9.shapes.add_textbox(Inches(7.0), Inches(2.5), Inches(5.3), Inches(3.5))
            tb_img.text_frame.text = "[Attack Graph Visualization: attack_graph.png]"
    else:
        tb_img = s9.shapes.add_textbox(Inches(7.0), Inches(2.5), Inches(5.3), Inches(3.5))
        tb_img.text_frame.text = "[Attack Graph Visualization: attack_graph.png]"

    add_notes(s9, """
Component 3 is our Attack and Dependency Graph Engine.
Traditional tools look at resources in silos. We use NetworkX to construct a directed multi-graph of the entire cloud estate.
The graph models how an attacker on the public internet can enter through an open security group, compromise an EC2 instance, assume an IAM role, and access a crown jewel S3 bucket or SQS queue.
On the right, you can see the actual attack graph generated by our tool during the testbed scan.
    """)

    # ==========================================
    # SLIDE 10: COMPONENT 4 — RISK ENGINE
    # ==========================================
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "Component Deep Dive 04", "Contextual Risk Prioritization Algorithm", "cloudsec_copilot/risk/risk_engine.py — Contextual multi-factor scoring")

    # Formula Card
    add_card(s10, Inches(0.8), Inches(1.8), Inches(11.7), Inches(1.2), COLOR_CARD_BG, COLOR_ACCENT_RED)
    tb_f = s10.shapes.add_textbox(Inches(1.0), Inches(1.9), Inches(11.3), Inches(1.0))
    tf_f = tb_f.text_frame
    tf_f.word_wrap = True
    p = tf_f.paragraphs[0]
    p.text = "MATHEMATICAL RISK FORMULATION (0.0 — 10.0 SCALE):"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_CYAN
    p2 = tf_f.add_paragraph()
    p2.text = "Risk Score = Min(10.0, Base Severity Weight + Internet Exposure (+1.5) + Privilege Multiplier (+1.5) + Blast Radius Reachability (+0.5/node))"
    p2.font.name = "Consolas"
    p2.font.size = Pt(13)
    p2.font.bold = True
    p2.font.color.rgb = COLOR_TEXT_WHITE

    # Left Card: Formula Weights
    add_card(s10, Inches(0.8), Inches(3.2), Inches(5.7), Inches(3.5))
    tb_l = s10.shapes.add_textbox(Inches(1.0), Inches(3.4), Inches(5.3), Inches(3.1))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "DYNAMIC MULTI-FACTOR WEIGHTS"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_BLUE
    p.space_after = Pt(6)
    r_weights = [
        "Base Severity Weight: CRITICAL = 6.0 | HIGH = 4.0 | MEDIUM = 2.5 | LOW = 1.0.",
        "Internet Ingress Bonus (+1.5): Triggered if the resource directly allows 0.0.0.0/0 traffic or public ACLs.",
        "Privilege Escalation (+1.5): Triggered if the resource holds AdministratorAccess or IAM credential creation rights.",
        "Graph Blast Radius (+0.5 per node, max +2.5): Measured by walking the NetworkX neighbor graph to count reachable downstream assets."
    ]
    for w in r_weights:
        p = tf_l.add_paragraph()
        p.text = "• " + w
        p.font.size = Pt(10.5)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(4)

    # Right Card: Sample Priority Queue
    add_card(s10, Inches(6.8), Inches(3.2), Inches(5.7), Inches(3.5))
    tb_r = s10.shapes.add_textbox(Inches(7.0), Inches(3.4), Inches(5.3), Inches(3.1))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "REAL-WORLD PRIORITIZATION OUTCOME"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_GREEN
    p.space_after = Pt(6)
    outcomes = [
        "Rank 1 (Score 7.2/10): Open Security Group (sg-4f6433aa) — Public internet ingress point exposing compute cluster.",
        "Rank 2 (Score 6.4/10): Public S3 Bucket (cloudsec-vulnerable) — Direct data exfiltration risk.",
        "Rank 3 (Score 6.15/10): IAM Admin Role (CloudSecVulnerableAdminRole) — High privilege multiplier.",
        "Rank 4 (Score 5.2/10): SQS Permissive Policy & IAM Stale Keys — Prioritized below direct entry points.",
        "Outcome: Eliminates alert fatigue by telling engineers exactly what to fix first!"
    ]
    for oc in outcomes:
        p = tf_r.add_paragraph()
        p.text = "• " + oc
        p.font.size = Pt(10.5)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(4)

    add_notes(s10, """
Slide 10 details our Risk Prioritization Engine.
CVSS scores are notoriously unhelpful in the cloud because they do not account for environmental reachability.
An unencrypted S3 bucket buried deep inside a private VPC is much less dangerous than an open security group guarding an admin host.
Our mathematical formula factors in base severity, direct internet exposure, administrative privilege level, and graph blast radius.
This yields a clear, descending priority queue of vulnerabilities.
    """)

    # ==========================================
    # SLIDE 11: COMPONENT 5 — AI REASONER & PLANNER
    # ==========================================
    s11 = prs.slides.add_slide(blank_layout)
    set_slide_background(s11)
    add_header(s11, "Component Deep Dive 05", "Contextual AI Reasoning & Remediation Planner", "cloudsec_copilot/ai/ai_reasoner.py & remediation/remediation.py")

    add_card(s11, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s11.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "GROUNDED LLM REASONING VIA OPENROUTER"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_PURPLE
    p.space_after = Pt(8)
    ai_points = [
        "Graph-Grounded Prompts: The AI reasoner receives not just the finding, but the complete attack path, reachable neighbor nodes, and risk score.",
        "Dual-Layer Execution: Leverages OpenRouter API (Claude 3.5 Sonnet / GPT-4o) with an automatic offline deterministic heuristic fallback.",
        "Structured Remediation Planning: Outputs a 6-part schema: executive summary, business impact, step-by-step fix instructions, action parameters, rollback command, and provider metadata.",
        "Dry-Run Mode: The RemediationPlanner generates exact execution plans with --dry-run support, allowing preview without making changes."
    ]
    for pt in ai_points:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(6)

    # Right Card: Sample AI Output Box
    add_card(s11, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9), COLOR_CODE_BG, COLOR_ACCENT_PURPLE)
    tb_r = s11.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "STRUCTURED AI REASONING OUTPUT"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_CYAN
    p.space_after = Pt(6)
    ai_json_sample = (
        "{\n"
        '  "summary": "Public S3 bucket allows unauthorized read",\n'
        '  "impact": "Data exfiltration of confidential artifacts",\n'
        '  "action": {\n'
        '    "type": "RESTRICT_S3_BUCKET_ACCESS",\n'
        '    "resource_id": "cloudsec-vulnerable-public-bucket",\n'
        '    "parameters": {\n'
        '      "BlockPublicAcls": true,\n'
        '      "IgnorePublicAcls": true,\n'
        '      "BlockPublicPolicy": true,\n'
        '      "RestrictPublicBuckets": true\n'
        "    }\n"
        "  },\n"
        '  "rollback": {\n'
        '    "action": "RESTORE_S3_PREVIOUS_ACL",\n'
        '    "cached_state": {"ACL": "public-read"}\n'
        "  }\n"
        "}"
    )
    p2 = tf_r.add_paragraph()
    p2.text = ai_json_sample
    p2.font.name = "Consolas"
    p2.font.size = Pt(9.5)
    p2.font.color.rgb = COLOR_CODE_TEXT

    add_notes(s11, """
Component 5 combines our OpenRouter AI Reasoner and Remediation Planner.
Instead of sending generic prompts, we inject rich graph context—showing the LLM the exact attack path and blast radius.
The LLM generates an explanation of root cause, business impact, and a structured remediation payload.
If an internet connection is unavailable or API tokens are omitted, the system seamlessly falls back to a deterministic planner.
    """)

    # ==========================================
    # SLIDE 12: COMPONENT 6 — AI SAFETY VALIDATOR
    # ==========================================
    s12 = prs.slides.add_slide(blank_layout)
    set_slide_background(s12)
    add_header(s12, "Component Deep Dive 06", "AI Safety Validator & Pre-Execution Guardrails", "cloudsec_copilot/ai/safety_validator.py — Mitigating autonomous agent security risks")

    add_card(s12, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s12.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "AGENTIC AI SAFETY FILTERS"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_ORANGE
    p.space_after = Pt(8)
    v_points = [
        "In response to Microsoft Research (2026): Autonomous AI agents can perform destructive or out-of-scope actions if not strictly validated.",
        "Zero Blind Execution: No AI-suggested command is ever routed directly to cloud APIs without passing the AISafetyValidator.",
        "Destructive Action Filtering: Explicitly rejects any command containing destructive API verbs (e.g., DeleteBucket, TerminateInstances, DropDatabase, DeleteRole).",
        "Target Resource Matching: Verifies that the resource targeted by the AI matches the exact resource flagged in the scanned finding.",
        "Parameter Type & Range Verification: Ensures booleans, IP CIDR blocks, port ranges, and policy strings conform to valid AWS syntax."
    ]
    for pt in v_points:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(6)

    # Right Card: Validation Rules Box
    add_card(s12, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9), COLOR_CARD_BG, COLOR_ACCENT_RED)
    tb_r = s12.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "VALIDATION GATE ENFORCEMENT"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_GREEN
    p.space_after = Pt(6)
    gates = [
        ("GATE 1: Action Whitelist", "Action must be in APPROVED_ACTIONS (e.g., RESTRICT_S3, REVOKE_SG_INGRESS, DETACH_ADMIN_POLICY)."),
        ("GATE 2: Destructive Action Blacklist", "Hard block on any action containing 'DELETE', 'TERMINATE', 'PURGE', or 'DROP'."),
        ("GATE 3: Resource Scope Verification", "Resource ID must exist in current snapshot; prevents cross-tenant or out-of-scope modifications."),
        ("GATE 4: Reversibility Prerequisite", "Action must provide complete previous-state metadata to enable automated rollback."),
        ("OUTCOME:", "Returns APPROVED or REJECTED with specific validation errors before execution.")
    ]
    for g_title, g_desc in gates:
        p = tf_r.add_paragraph()
        p.text = g_title + ": "
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = COLOR_ACCENT_CYAN
        run = p.add_run()
        run.text = g_desc
        run.font.bold = False
        run.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(4)

    add_notes(s12, """
Component 6 implements our AI Safety Validator.
As autonomous AI agents become prevalent, security researchers have demonstrated the high risks of agent tool misuse.
We built a deterministic security gate between the AI Reasoner and the Cloud Executor.
Every proposed remediation must pass through 4 strict safety gates: action whitelisting, destructive action blacklisting, resource scope verification, and a mandatory reversibility prerequisite.
    """)

    # ==========================================
    # SLIDE 13: COMPONENT 7 — REMEDIATION EXECUTOR
    # ==========================================
    s13 = prs.slides.add_slide(blank_layout)
    set_slide_background(s13)
    add_header(s13, "Component Deep Dive 07", "Remediation Execution Engine with HITL Controls", "cloudsec_copilot/executor/executor.py — Real Boto3 remediation handlers")

    add_card(s13, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s13.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "HUMAN-IN-THE-LOOP (HITL) EXECUTION"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_GREEN
    p.space_after = Pt(8)
    e_points = [
        "Mandatory Human Authorization: Actions require explicit confirmation via interactive prompt [y/N] or the deliberate --yes CLI flag.",
        "State Snapshotting: Before any modification is sent to AWS APIs, the executor snapshots the exact existing configuration (ACLs, policies, rules).",
        "Dry-Run Mode (--dry-run): Simulates the API execution, printing exact Boto3 payloads without mutating cloud infrastructure.",
        "Graceful Error Handling: Catches AWS ClientErrors, handles already-secured resources idempotently, and logs structured results."
    ]
    for pt in e_points:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(6)

    # Right Card: Handlers Breakdown
    add_card(s13, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_r = s13.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "SUPPORTED BOTO3 REMEDIATION HANDLERS"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_BLUE
    p.space_after = Pt(8)
    handlers = [
        ("S3 Public Bucket Remediation", "Applies put_public_access_block (blocking all public ACLs & policies) and resets bucket ACL to 'private'."),
        ("Security Group Ingress Revocation", "Invokes revoke_security_group_ingress to remove 0.0.0.0/0 rules on port 22/80/3389 while preserving specific internal CIDRs."),
        ("IAM Least-Privilege Detachment", "Executes detach_role_policy for AdministratorAccess and attaches scoped least-privilege policies (e.g., ReadOnlyAccess)."),
        ("SQS Policy Restriction", "Invokes set_queue_attributes to strip wildcard Principal: * and enforce explicit account-scoped access control.")
    ]
    for h_name, h_desc in handlers:
        p = tf_r.add_paragraph()
        p.text = h_name + ": "
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = COLOR_ACCENT_CYAN
        run = p.add_run()
        run.text = h_desc
        run.font.bold = False
        run.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(5)

    add_notes(s13, """
Component 7 is the Remediation Execution Engine.
It uses real Boto3 clients to apply security fixes directly to the cloud environment.
Crucially, it enforces Human-in-the-Loop governance: no fix is applied without explicit developer confirmation or the deliberate --yes flag.
Before executing, it snapshots the current state of the resource so that we have full reversibility if needed.
    """)

    # ==========================================
    # SLIDE 14: COMPONENT 8 — SAFE ROLLBACK SUBSYSTEM
    # ==========================================
    s14 = prs.slides.add_slide(blank_layout)
    set_slide_background(s14)
    add_header(s14, "Component Deep Dive 08", "Safe Rollback Subsystem & State Reversibility", "Automated reversal of applied remediations to prevent production outages")

    add_card(s14, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s14.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "THE REVERSIBILITY GUARANTEE"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_CYAN
    p.space_after = Pt(8)
    rb_points = [
        "Why Rollback is Essential: Security remediations can inadvertently break production dependencies (e.g., a service requiring an open ingress port).",
        "Pre-State Caching: When a fix executes, original_state is saved inside the audit trail (e.g., exact CIDR IP permissions, previous ACL grants).",
        "One-Command Rollback: Executing 'cloudsec rollback --id <VULN_ID>' retrieves the latest audit record and restores the original state.",
        "Rollback Handlers: Dedicated reversal methods reconstruct revoked ingress rules, remove public-access blocks, or reattach prior IAM roles.",
        "Closed-Loop Rollback Verification: The verifier confirms that the rollback state matches the pre-remediation snapshot."
    ]
    for pt in rb_points:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(6)

    # Right Card: Rollback Flow
    add_card(s14, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9), COLOR_CODE_BG, COLOR_CARD_BORDER)
    tb_r = s14.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "ROLLBACK EXECUTION FLOW"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_GREEN
    p.space_after = Pt(6)
    rb_steps = (
        "$ cloudsec rollback --id VULN-001\n"
        "[+] Found audit record for VULN-001\n"
        "    Resource: cloudsec-vulnerable-public-bucket\n"
        "    Applied Fix: RESTRICT_S3_BUCKET_ACCESS\n"
        "    Original State: BlockPublicAcls=False, ACL=public-read\n\n"
        "[?] Confirm rollback of VULN-001? [y/N]: y\n"
        "[*] Reversing S3 public access block...\n"
        "[*] Restoring previous bucket ACL grants...\n"
        "[SUCCESS] Rollback completed successfully.\n"
        "[*] Running post-rollback verification...\n"
        "[VERIFIED] Cloud state restored to pre-fix baseline.\n"
        "[AUDIT] Rollback event logged to audit_log.json."
    )
    p2 = tf_r.add_paragraph()
    p2.text = rb_steps
    p2.font.name = "Consolas"
    p2.font.size = Pt(9.5)
    p2.font.color.rgb = COLOR_CODE_TEXT

    add_notes(s14, """
Component 8 is our Safe Rollback Subsystem.
One of the biggest blockers to automated cloud remediation is developer fear: 'What if the fix breaks a microservice in production?'
CloudSec-Copilot solves this by guaranteeing 100% reversibility.
Because we cache the original state prior to execution, developers can type 'cloudsec rollback --id VULN-001' and the system immediately restores the prior state while logging the rollback event.
    """)

    # ==========================================
    # SLIDE 15: COMPONENT 9 — AUDIT LOGGING
    # ==========================================
    s15 = prs.slides.add_slide(blank_layout)
    set_slide_background(s15)
    add_header(s15, "Component Deep Dive 09", "Immutable Audit Logging Subsystem", "audit_log.json — Structured compliance trails with credential sanitization")

    add_card(s15, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s15.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "AUDIT COMPLIANCE & GOVERNANCE"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_BLUE
    p.space_after = Pt(8)
    a_points = [
        "SOC2 & ISO 27001 Alignment: Enterprise security compliance mandates that every cloud modification be timestamped, attributed, and recorded.",
        "Append-Only JSON Records: Each execution appends a JSON record containing timestamp, finding_id, rule_id, risk_score, approval_status, and full before/after snapshots.",
        "Automated Credential Masking: A built-in sanitization filter redacts sensitive strings (e.g., AWS_SECRET_ACCESS_KEY, OPENROUTER_API_KEY, Bearer tokens).",
        "Deterministic Audit Recovery: Used by the rollback engine to query the exact historical baseline for any finding ID."
    ]
    for pt in a_points:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(6)

    # Right Card: Sample Audit Record
    add_card(s15, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9), COLOR_CODE_BG, COLOR_CARD_BORDER)
    tb_r = s15.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "SAMPLE AUDIT RECORD SCHEMA"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_CYAN
    p.space_after = Pt(6)
    audit_json = (
        "{\n"
        '  "timestamp": "2026-10-15T18:42:10Z",\n'
        '  "finding_id": "VULN-001",\n'
        '  "rule_id": "RULE-S3-PUBLIC",\n'
        '  "resource_id": "cloudsec-vulnerable-bucket",\n'
        '  "risk_score": 6.4,\n'
        '  "action": "RESTRICT_S3_BUCKET_ACCESS",\n'
        '  "approval_status": "APPROVED",\n'
        '  "dry_run": false,\n'
        '  "original_state": {\n'
        '    "BlockPublicAcls": false,\n'
        '    "ACL": "public-read"\n'
        "  },\n"
        '  "execution_result": "APPLIED",\n'
        '  "verification_result": "VERIFIED"\n'
        "}"
    )
    p2 = tf_r.add_paragraph()
    p2.text = audit_json
    p2.font.name = "Consolas"
    p2.font.size = Pt(9.5)
    p2.font.color.rgb = COLOR_CODE_TEXT

    add_notes(s15, """
Component 9 is our Audit Logging Subsystem.
Security without auditability is unacceptable in enterprise cloud environments.
Every action taken by CloudSec-Copilot is logged in audit_log.json with an immutable timestamp, risk score, approval status, and state snapshots.
Furthermore, we built automated regex masking to ensure that no API keys or access tokens ever leak into log files.
    """)

    # ==========================================
    # SLIDE 16: COMPONENT 10 — POST-REMEDIATION VERIFIER
    # ==========================================
    s16 = prs.slides.add_slide(blank_layout)
    set_slide_background(s16)
    add_header(s16, "Component Deep Dive 10", "Post-Remediation Verification Engine", "cloudsec_copilot/verifier/verifier.py — The 'Trust but Verify' paradigm")

    add_card(s16, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s16.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "DELTA-STATE VERIFICATION LOGIC"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_GREEN
    p.space_after = Pt(8)
    v_points2 = [
        "The Principle: Never assume an API call succeeded in eliminating security risk. Cloud API calls can fail silently or get superseded by other policies.",
        "Delta Scanning: Immediately following remediation, the verifier triggers a clean discovery and rescan of the target asset.",
        "Mathematical Verification: Compares pre-fix findings (F_before) with post-fix findings (F_after). If the finding is absent, status is marked VERIFIED.",
        "Failure Alerting: If the vulnerability still appears during the rescan, the system flags remediation failure and triggers an alert.",
        "Rollback Validation: Also validates that rollback events successfully returned the resource to its initial state."
    ]
    for pt in v_points2:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(6)

    # Right Card: Verification Workflow
    add_card(s16, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9), COLOR_CODE_BG, COLOR_CARD_BORDER)
    tb_r = s16.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "VERIFIER EXECUTION LOGIC"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_CYAN
    p.space_after = Pt(6)
    ver_code = (
        "class Verifier:\n"
        "    def verify_finding_removed(\n"
        "        self, before_findings, after_findings, target_id\n"
        "    ) -> dict:\n"
        "        was_present = any(f['id'] == target_id for f in before_findings)\n"
        "        is_present  = any(f['id'] == target_id for f in after_findings)\n\n"
        "        if was_present and not is_present:\n"
        "            return {\n"
        "                'status': 'VERIFIED',\n"
        "                'message': f'Finding {target_id} successfully resolved.',\n"
        "                'remediation_required': False\n"
        "            }\n"
        "        else:\n"
        "            return {\n"
        "                'status': 'FAILED',\n"
        "                'message': f'Vulnerability {target_id} persists.',\n"
        "                'remediation_required': True\n"
        "            }"
    )
    p2 = tf_r.add_paragraph()
    p2.text = ver_code
    p2.font.name = "Consolas"
    p2.font.size = Pt(9.5)
    p2.font.color.rgb = COLOR_CODE_TEXT

    add_notes(s16, """
Component 10 is our Verification Engine.
Most security tools simply send an API call and print 'Done'. In the real cloud, API calls can succeed yet leave vulnerabilities open due to conflicting IAM policies or caching.
CloudSec-Copilot re-scans the live cloud resource to mathematically verify that the finding is gone.
Only when the vulnerability is confirmed absent from the delta scan does the system declare victory.
    """)

    # ==========================================
    # SLIDE 17: COMPONENT 11 — RICH CLI & UX
    # ==========================================
    s17 = prs.slides.add_slide(blank_layout)
    set_slide_background(s17)
    add_header(s17, "Component Deep Dive 11", "Interactive CLI & Developer Experience", "cloudsec_copilot/cli/main.py — Built with Click, Rich tables, and interactive prompts")

    add_card(s17, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s17.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "UNIFIED COMMAND-LINE INTERFACE"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_BLUE
    p.space_after = Pt(8)
    cli_cmds = [
        ("cloudsec scan --explain", "Runs discovery + deterministic scan; prints risk-ranked findings with score breakdowns."),
        ("cloudsec scan --visualize <png> --graph-json <json>", "Exports the NetworkX attack graph image and attack paths as JSON."),
        ("cloudsec fix --id <ID> [--yes]", "AI reasoning + safety validation, state snapshot, Boto3 fix, audit log."),
        ("cloudsec fix-all [--yes]", "Remediates every supported finding in a single guarded run."),
        ("cloudsec rollback --id <ID> | --last", "Restores the exact pre-remediation configuration from the audit trail."),
        ("cloudsec verify / cloudsec report", "Delta rescan to confirm resolution; export JSON / Markdown / HTML report.")
    ]
    for c_name, c_desc in cli_cmds:
        p = tf_l.add_paragraph()
        p.text = c_name + ": "
        p.font.size = Pt(10.5)
        p.font.bold = True
        p.font.color.rgb = COLOR_ACCENT_CYAN
        run = p.add_run()
        run.text = c_desc
        run.font.bold = False
        run.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(4)

    # Right Card: CLI Terminal Visual
    add_card(s17, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9), COLOR_CODE_BG, COLOR_CARD_BORDER)
    tb_r = s17.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "TERMINAL SCAN OUTPUT EXAMPLE"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_GREEN
    p.space_after = Pt(6)
    cli_sample = (
        "┌──────────┬──────────┬──────────────────────┬────────────┐\n"
        "│ Vuln ID  │ Severity │ Resource             │ Risk Score │\n"
        "├──────────┼──────────┼──────────────────────┼────────────┤\n"
        "│ VULN-003 │ HIGH     │ sg-4f6433aa675e9c89a │ 7.20 / 10  │\n"
        "│ VULN-001 │ CRITICAL │ cloudsec-vulnerable  │ 6.40 / 10  │\n"
        "│ VULN-005 │ CRITICAL │ CloudSecAdminRole    │ 6.15 / 10  │\n"
        "│ VULN-006 │ HIGH     │ user_with_keys       │ 5.20 / 10  │\n"
        "│ VULN-007 │ HIGH     │ vulnerable-open-queue│ 5.20 / 10  │\n"
        "└──────────┴──────────┴──────────────────────┴────────────┘\n\n"
        "[+] Attack Graph: 6 Nodes, 5 Edges, 2 Attack Paths\n"
        "[+] Scan report saved to scan_report.json"
    )
    p2 = tf_r.add_paragraph()
    p2.text = cli_sample
    p2.font.name = "Consolas"
    p2.font.size = Pt(9.5)
    p2.font.color.rgb = COLOR_CODE_TEXT

    add_notes(s17, """
Component 11 is our Rich Command Line Interface.
We used Click and Rich to build an intuitive terminal interface.
Commands are modular and self-documenting.
The CLI formats tables with clear severity colors, renders attack paths, shows progress spinners during Boto3 calls, and prompts developers with clear yes/no confirmation gates before any change is applied.
    """)

    # ==========================================
    # SLIDE 18: CLOUD TESTBED (LOCALSTACK)
    # ==========================================
    s18 = prs.slides.add_slide(blank_layout)
    set_slide_background(s18)
    add_header(s18, "Emulated Cloud Testbed", "Safe, Isolated Testing with LocalStack & Docker", "scripts/setup_vulnerable_lab.py — Zero-cost, zero-risk reproducible evaluation")

    add_card(s18, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s18.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "THE REPRODUCIBLE VULNERABLE LAB"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_BLUE
    p.space_after = Pt(8)
    lab_points = [
        "Zero-Risk Testing: Running security exploits and automated remediations on real AWS production accounts risks catastrophic data loss and unexpected cloud bills.",
        "LocalStack Cloud Emulation: Simulates authentic AWS APIs (S3, IAM, EC2, SG, SQS) entirely inside Docker on localhost:4566.",
        "Automated Provisioning: scripts/setup_vulnerable_lab.py provisions a complete multi-tier vulnerable enterprise infrastructure in seconds.",
        "Reproducible Grading: Evaluators can clone the repository, run docker compose up, run setup_vulnerable_lab.py, and immediately inspect results."
    ]
    for pt in lab_points:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(6)

    # Right Card: Lab Resources Breakdown
    add_card(s18, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_r = s18.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "SIMULATED VULNERABLE ASSETS"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_ORANGE
    p.space_after = Pt(8)
    res_list = [
        ("S3 Public Bucket", "cloudsec-vulnerable-public-bucket: ACL public-read, block public access disabled."),
        ("Open Security Group", "sg-open-ingress: Inbound port 22 & 80 allowed from 0.0.0.0/0."),
        ("Admin IAM Role", "CloudSecVulnerableAdminRole: AdministratorAccess managed policy attached."),
        ("Overly Permissive SQS", "vulnerable-open-queue: Policy allows Principal: * with broad Receive/Send permissions."),
        ("Stale IAM User Keys", "vulnerable_user_with_keys: Created with active access keys that simulate unrotated credentials."),
        ("EC2 Instance Binding", "Simulated compute instance associated with the open SG and Admin role to form an attack chain.")
    ]
    for r_name, r_desc in res_list:
        p = tf_r.add_paragraph()
        p.text = r_name + ": "
        p.font.size = Pt(10.5)
        p.font.bold = True
        p.font.color.rgb = COLOR_ACCENT_CYAN
        run = p.add_run()
        run.text = r_desc
        run.font.bold = False
        run.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(4)

    add_notes(s18, """
Slide 18 explains our emulated cloud testbed.
Testing cloud security tools on live AWS accounts poses severe financial and operational hazards.
We utilized LocalStack in Docker to create an isolated, faithful AWS testbed.
Our setup script automatically spins up vulnerable S3 buckets, open security groups, admin IAM roles, and open SQS queues.
This allows anyone to test and grade our project with 100% reproducibility.
    """)

    # ==========================================
    # SLIDE 19: TESTING SUITE & QUALITY ASSURANCE
    # ==========================================
    s19 = prs.slides.add_slide(blank_layout)
    set_slide_background(s19)
    add_header(s19, "Testing & Quality Assurance", "Comprehensive Automated Test Suite: 100 Passing Tests", "Rigorous validation across Unit, Graph, Safety, Remediation, and Rollback modules")

    # Table of Test Modules
    table_shape = s19.shapes.add_table(7, 4, Inches(0.8), Inches(1.8), Inches(11.7), Inches(4.8))
    table = table_shape.table
    table.columns[0].width = Inches(3.2)
    table.columns[1].width = Inches(1.4)
    table.columns[2].width = Inches(5.1)
    table.columns[3].width = Inches(2.0)

    headers = ["Test Module File", "Tests", "Functional Scope Validated", "Status"]
    for c_idx, h_text in enumerate(headers):
        cell = table.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = COLOR_CARD_BG
        p = cell.text_frame.paragraphs[0]
        p.text = h_text
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = COLOR_ACCENT_CYAN

    tests_data = [
        ("test_phase1_detection.py", "10 Tests", "Deterministic detection of S3, SG, IAM, RDS, and SQS rules.", "10 / 10 PASSED"),
        ("test_phase2_graph_risk.py", "19 Tests", "NetworkX node creation, edge linking, blast radius calculation, risk scoring.", "19 / 19 PASSED"),
        ("test_phase3_graph_integration.py", "14 Tests", "End-to-end multi-hop traversal, crown-jewel targeting, attack path tracing.", "14 / 14 PASSED"),
        ("test_phase3_new_vulns.py", "15 Tests", "Extended rules: SQS queue policies, IAM stale keys, unencrypted storage.", "15 / 15 PASSED"),
        ("test_phase3_remediation.py", "21 Tests", "Safety validator, dry-run plans, Boto3 executor, audit schema, safe rollback.", "21 / 21 PASSED"),
        ("test_discovery.py & test_pipeline.py", "19 Tests", "Boto3 discovery collector, Pydantic snapshot export, verifier delta logic.", "19 / 19 PASSED"),
    ]

    for r_idx, row in enumerate(tests_data):
        for c_idx, val in enumerate(row):
            cell = table.cell(r_idx + 1, c_idx)
            cell.fill.solid()
            cell.fill.fore_color.rgb = COLOR_BG_DARK if (r_idx % 2 == 0) else COLOR_CARD_BG
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.size = Pt(10)
            if c_idx == 0:
                p.font.bold = True
                p.font.color.rgb = COLOR_ACCENT_BLUE
            elif c_idx == 3:
                p.font.bold = True
                p.font.color.rgb = COLOR_ACCENT_GREEN
            else:
                p.font.color.rgb = COLOR_TEXT_WHITE

    add_notes(s19, """
Slide 19 highlights our testing and QA methodology.
We built a comprehensive automated test suite consisting of 100 unit and integration tests.
Every phase of development has dedicated tests—from initial rule detection to graph traversal, safety validation, Boto3 remediation, and rollback.
All 100 tests pass in about 15 seconds when run from the repository root with LocalStack running (98 run offline without LocalStack).
    """)

    # ==========================================
    # SLIDE 20: LIVE DEMO FLOW
    # ==========================================
    s20 = prs.slides.add_slide(blank_layout)
    set_slide_background(s20)
    add_header(s20, "Live Demonstration Walkthrough", "End-to-End Execution Sequence", "A reproducible 7-step walkthrough demonstrating the full closed loop")

    demo_steps = [
        ("1. Test Suite Verification", "pytest -q   (run from repo root)", "Runs all 100 automated tests, including live LocalStack pipeline tests."),
        ("2. Cloud Testbed Spin-Up", "docker compose up -d", "Starts LocalStack emulating AWS cloud services on localhost:4566."),
        ("3. Vulnerable Lab Setup", "python scripts/setup_vulnerable_lab.py", "Provisions realistic vulnerable S3, IAM, SG, and SQS cloud assets."),
        ("4. Inventory Discovery & Scan", "python -m cloudsec_copilot.cli.main scan --explain", "Discovers resources and shows risk-ranked findings with score breakdown."),
        ("5. Attack Graph Export", "python -m cloudsec_copilot.cli.main scan --visualize attack_graph.png", "Renders multi-hop lateral movement paths to attack_graph.png."),
        ("6. Guarded Remediation", "python -m cloudsec_copilot.cli.main fix --id VULN-001", "AI plan + safety validation, approval prompt, Boto3 fix, audit trail."),
        ("7. Post-Fix Verification", "python -m cloudsec_copilot.cli.main verify", "Re-scans cloud state to confirm the vulnerability is removed."),
        ("8. Reversible Rollback", "python -m cloudsec_copilot.cli.main rollback --id VULN-001 --yes", "Restores pre-remediation configuration from the audit log."),
        ("9. Security Report", "python -m cloudsec_copilot.cli.main report --format html --output report.html", "Exports the findings and remediation status as an HTML report.")
    ]

    # Render in a clean 3x3 or 2-column grid
    for i, (title, cmd, desc) in enumerate(demo_steps):
        row = i // 2
        col_idx = i % 2
        if i == 8:
            left = Inches(0.8 + 0.5 * 6.0)
            width = Inches(5.7)
            top = Inches(1.8 + 4 * 1.02)
        else:
            left = Inches(0.8 + col_idx * 6.0)
            width = Inches(5.7)
            top = Inches(1.8 + row * 1.02)

        add_card(s20, left, top, width, Inches(0.92))
        tb = s20.shapes.add_textbox(left + Inches(0.12), top + Inches(0.06), width - Inches(0.24), Inches(0.8))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = cmd
        p.font.name = "Consolas"
        p.font.size = Pt(10.5)
        p.font.bold = True
        p.font.color.rgb = COLOR_CODE_TEXT

        p2 = tf.add_paragraph()
        p2.text = desc
        p2.font.name = "Calibri"
        p2.font.size = Pt(9.5)
        p2.font.color.rgb = COLOR_TEXT_WHITE

    add_notes(s20, """
This slide shows the exact walkthrough we will perform during the live demo.
We start by setting up the vulnerable lab, scanning the resources, generating the attack graph, reasoning through the AI copilot, executing a guarded fix, verifying the fix, and finally demonstrating safe rollback.
    """)

    # ==========================================
    # SLIDE 21: MID-TERM VS FINAL DELIVERABLES
    # ==========================================
    s21 = prs.slides.add_slide(blank_layout)
    set_slide_background(s21)
    add_header(s21, "Deliverables Accountability", "Mid-Term Commitments vs. Final Review Deliverables", "Verifying completion of every feature marked as 'remaining' in CloudSec.pdf")

    table_shape = s21.shapes.add_table(7, 4, Inches(0.8), Inches(1.8), Inches(11.7), Inches(4.8))
    table = table_shape.table
    table.columns[0].width = Inches(3.0)
    table.columns[1].width = Inches(2.5)
    table.columns[2].width = Inches(4.4)
    table.columns[3].width = Inches(1.8)

    headers = ["Mid-Term Plan / Milestone", "Mid-Term Status (CloudSec.pdf)", "Final Delivery in CloudSec-Copilot", "Final Status"]
    for c_idx, h_text in enumerate(headers):
        cell = table.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = COLOR_CARD_BG
        p = cell.text_frame.paragraphs[0]
        p.text = h_text
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = COLOR_ACCENT_CYAN

    commitments = [
        ("More Vulnerability Rules", "Marked 'Remaining / In Progress'", "Implemented SQS permissive rules, IAM stale keys, unencrypted buckets, RDS.", "100% DONE"),
        ("Stronger Attack-Path Analysis", "Marked 'In Progress'", "Full NetworkX multi-hop traversal, blast radius algorithm, graph export.", "100% DONE"),
        ("AI Safety Validation & Dry-Run", "Marked 'Remaining'", "AISafetyValidator with destructive action blocking and dry-run planning.", "100% DONE"),
        ("Rollback & Audit History", "Marked 'Remaining'", "State snapshotting, audit_log.json trail, one-command rollback.", "100% DONE"),
        ("Reports & Rich CLI", "Marked 'Partial'", "Click + Rich interactive CLI, scan_report.json, attack_graph.png.", "100% DONE"),
        ("Comprehensive Testing", "21 tests passing at mid-term", "100 passing tests across Unit, Graph, Remediation, Rollback, and live LocalStack.", "100% DONE"),
    ]

    for r_idx, row in enumerate(commitments):
        for c_idx, val in enumerate(row):
            cell = table.cell(r_idx + 1, c_idx)
            cell.fill.solid()
            cell.fill.fore_color.rgb = COLOR_BG_DARK if (r_idx % 2 == 0) else COLOR_CARD_BG
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.size = Pt(10)
            if c_idx == 0:
                p.font.bold = True
                p.font.color.rgb = COLOR_ACCENT_BLUE
            elif c_idx == 1:
                p.font.color.rgb = COLOR_ACCENT_ORANGE
            elif c_idx == 3:
                p.font.bold = True
                p.font.color.rgb = COLOR_ACCENT_GREEN
            else:
                p.font.color.rgb = COLOR_TEXT_WHITE

    add_notes(s21, """
In our earlier mid-term presentation (CloudSec.pdf), Slide 15 contained a list of items marked as 'remaining'.
As you can see from this accountability matrix, every single one of those commitments has been fulfilled in full.
We added the new vulnerability rules, upgraded the attack graph to a full multi-hop traversal engine, built the AI safety validator, implemented state snapshotting and rollback, expanded the CLI, and scaled our test suite from 21 tests to 100 passing tests.
    """)

    # ==========================================
    # SLIDE 22: LIMITATIONS & FUTURE ROADMAP
    # ==========================================
    s22 = prs.slides.add_slide(blank_layout)
    set_slide_background(s22)
    add_header(s22, "Roadmap & Future Work", "System Strengths, Current Limitations, and Future Directions", "Evolving CloudSec-Copilot toward enterprise multi-cloud environments")

    add_card(s22, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s22.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "CURRENT SYSTEM BOUNDARIES"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_ORANGE
    p.space_after = Pt(8)
    lim_points = [
        "Single-Cloud Focus: Current collectors target AWS-compatible APIs; does not yet ingest Azure Resource Manager or GCP Cloud Asset Inventory.",
        "LocalStack Emulation Nuances: Advanced enterprise features (like multi-AZ RDS or IAM cross-account federation) require LocalStack Pro or live AWS credentials.",
        "Runtime Only: Currently remediates live deployed resources, but does not yet backport fixes into Git/Terraform code repositories automatically.",
        "CLI Interface: While rich and interactive, developers in large enterprises frequently prefer web dashboards or IDE extensions."
    ]
    for pt in lim_points:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(6)

    add_card(s22, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_r = s22.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "FUTURE ENGINEERING ROADMAP"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_GREEN
    p.space_after = Pt(8)
    road_points = [
        "Multi-Cloud Ingestion: Expanding DiscoveryCollector to support Microsoft Azure (Azure SDK) and Google Cloud Platform (google-cloud-asset).",
        "Bidirectional Shift-Left PRs: Automatically generating Git pull requests with Terraform / OpenTofu HCL patches alongside runtime Boto3 fixes.",
        "IDE Extension & SaaS Dashboard: Building a VS Code extension and a React-based web console for visual attack graph exploration.",
        "Continuous Event-Driven Remediation: Integrating with AWS EventBridge and CloudWatch to trigger automated scans upon infrastructure drift."
    ]
    for pt in road_points:
        p = tf_r.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(6)

    add_notes(s22, """
Slide 22 addresses current limitations and future directions.
While our MVP is battle-tested on AWS and LocalStack, our future roadmap includes expanding to Azure and GCP, automatically opening Terraform pull requests for true shift-left synchronization, and building a VS Code extension for developers.
    """)

    # ==========================================
    # SLIDE 23: CONCLUSION & REFERENCES
    # ==========================================
    s23 = prs.slides.add_slide(blank_layout)
    set_slide_background(s23)
    add_header(s23, "Conclusion & Defense", "Summary of Contributions & Academic Citations", "CloudSec-Copilot: Closing the loop in modern cloud security")

    add_card(s23, Inches(0.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_l = s23.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "KEY CONTRIBUTIONS"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_CYAN
    p.space_after = Pt(8)
    concl_points = [
        "Closed the Gap: Successfully built an end-to-end pipeline transitioning from passive alerting to verified, reversible action.",
        "Attack Graph Context: Proved that graph-based lateral movement modeling uncovers toxic security combinations invisible to traditional scanners.",
        "Guardrailed Agentic AI: Demonstrated that LLM reasoning is viable for cloud remediation when paired with strict pre-execution safety filters.",
        "100% Reversible Assurance: Implemented state snapshotting and rollback to overcome developer hesitation around automated remediation.",
        "Engineering Rigor: 100 automated tests, clean modular architecture, and fully open-source reproducible code on GitHub."
    ]
    for pt in concl_points:
        p = tf_l.add_paragraph()
        p.text = "• " + pt
        p.font.size = Pt(10.5)
        p.font.color.rgb = COLOR_TEXT_WHITE
        p.space_after = Pt(5)

    add_card(s23, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.9))
    tb_r = s23.shapes.add_textbox(Inches(7.0), Inches(2.0), Inches(5.3), Inches(4.5))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "KEY REFERENCES & CITATIONS"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_ACCENT_BLUE
    p.space_after = Pt(8)
    refs = [
        "[1] Prowler Cloud Security (2026). Open-source security tool for AWS, Azure, GCP & Kubernetes.",
        "[2] Palo Alto Networks (2026). Checkov: Static Code Analysis for Infrastructure-as-Code.",
        "[3] Microsoft Research (2026). Security Risks in Tool-Enabled AI Agents and Autonomous Execution.",
        "[4] TerraRepair (2026). A Tool-Grounded LLM Agent for Infrastructure-as-Code Repair.",
        "[5] InfraFix (2025). Technology-Agnostic Repair of Infrastructure as Code.",
        "[6] Wiz Security Platform (2026). Agentless Cloud Discovery and Security Graph Architecture."
    ]
    for rf in refs:
        p = tf_r.add_paragraph()
        p.text = rf
        p.font.size = Pt(9.5)
        p.font.color.rgb = COLOR_TEXT_MUTED
        p.space_after = Pt(3)

    p_end = tf_r.add_paragraph()
    p_end.text = "\nThank you! We welcome any questions and discussion."
    p_end.font.size = Pt(12)
    p_end.font.bold = True
    p_end.font.color.rgb = COLOR_ACCENT_GREEN

    add_notes(s23, """
In conclusion, CloudSec-Copilot bridges the critical divide between finding cloud misconfigurations and safely fixing them.
By combining deterministic discovery, graph-based attack path modeling, safety-guardrailed AI reasoning, real Boto3 execution, and reversible rollback, we have built a developer-first platform for autonomous yet reliable cloud posture management.
Thank you for your time, and we are now ready for your questions.
    """)

    try:
        prs.save(OUTPUT_FILE)
        print(f"Successfully generated presentation: {OUTPUT_FILE}")
    except PermissionError:
        fallback_file = "CloudSec_Final_Review_Presentation_v2.pptx"
        prs.save(fallback_file)
        print(f"File '{OUTPUT_FILE}' is currently open in PowerPoint/another app.")
        print(f"Saved updated presentation to fallback file: {fallback_file}")

if __name__ == "__main__":
    create_presentation()
