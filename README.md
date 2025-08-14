# Detection Engineering Repository

This repository contains **production-style detection use cases** designed for real-world Security Operations Center (SOC) workflows.  
Each detection is documented with background, simulated logs, SPL/KQL/LogRhythm queries, triage reports, and alert templates.

---

## 📂 Repository Structure
usecases/
└── <MITRE_Technique_ID>_<Technique_Name>/
├── background.md # Context, MITRE mapping, prerequisites, and simulation steps
├── simulated_log.log # Sample or generated log data for testing
├── detection_spl.txt # SPL or other SIEM query logic
├── triage_report.md # 5W+1H investigation report template
└── alert_template.json # JSON alert definition for SIEM automation

<<<<<<< HEAD
=======
yaml
Copy
Edit

>>>>>>> 2d20783 (docs: add root README.md)
---

## ✅ Completed Use Cases
| MITRE ID | Technique Name              | Status   |
|----------|-----------------------------|----------|
| T1059    | Command Execution           | ✅ Added |

---

## 🛠 How to Use
1. **Pick a use case folder** (e.g., `T1059_Command_Execution`).
2. Review `background.md` for:
   - MITRE ATT&CK mapping
   - Hypothesis
   - Simulation steps
3. Load `simulated_log.log` into your lab SIEM or search head.
4. Paste `detection_spl.txt` into your SIEM (Splunk, Sentinel, LogRhythm, etc.).
5. Validate detection with test data.
6. Use `triage_report.md` to document investigations.
7. Deploy `alert_template.json` for continuous monitoring.

---

<<<<<<< HEAD
## 📌 Conventions
- **MITRE IDs** in folder names for quick mapping.
- **5W+1H** triage report format for consistency.
- Queries tagged with `# Objective` and `# Data Source` comments.
- Use meaningful commit messages (`feat:`, `fix:`, `docs:`).

---

## 🤝 Contributing
If you'd like to add a new detection:
1. Fork this repo.
2. Create a new branch:  
   ```bash
   git checkout -b feat/new-detection
   
Add a folder under usecases/ with the MITRE technique ID.

Include all five files (background.md, simulated_log.log, detection_spl.txt, triage_report.md, alert_template.json).

Commit & push your changes.

Open a Pull Request.
=======
## 📚 References
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Splunk Documentation](https://docs.splunk.com/)
- [Sigma Rules Project](https://github.com/SigmaHQ/sigma)

---

**Author:** [Kishore Bairi Cyber](https://github.com/kishore-bairi-cyber)  
**Focus:** Blue Team • Detection Engineering • DFIR • AI-SOC Automation
>>>>>>> 2d20783 (docs: add root README.md)
