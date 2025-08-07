# CRED-AUDIT: BRUTALIST PASSWORD SECURITY AUDITOR

**MVP SHOWCASE VERSION** - A terminal-inspired web application for password strength analysis and compliance checking.

> **NOTE**: This is a Minimum Viable Product (MVP) built for demonstration purposes. While fully functional for password analysis, it's designed as a showcase of brutalist web design and security audit concepts.

## FEATURES

- **PASSWORD STRENGTH ANALYZER**: Real scoring algorithm with detailed feedback
- **POLICY COMPLIANCE CHECKER**: Enterprise security policy validation  
- **BREACH DATABASE**: 100+ actual compromised passwords from known breaches
- **AUDIT DASHBOARD**: Live security metrics and logging
- **EXECUTIVE REPORTS**: Data-driven security assessment summaries
- **BRUTALIST DESIGN**: Pure terminal aesthetic - no BS, just functionality

## QUICK START

```bash
# Run the application (auto-creates venv and installs Flask)
python main.py
```

**Auto-setup includes:**
- Virtual environment creation
- Flask dependency installation  
- SQLite database initialization
- Browser auto-launch at http://127.0.0.1:5000

**Ready in 30 seconds.**

## WHAT IT ACTUALLY DOES

**REAL FUNCTIONALITY:**
- Analyzes password strength with legitimate scoring algorithm
- Checks against 100+ actual compromised passwords from breaches
- Validates enterprise security policies  
- Generates real audit reports from actual data
- Tracks metrics in SQLite database

**MVP LIMITATIONS:**
- Breach database contains ~100 passwords (not millions)
- No user authentication system
- Local deployment only
- Basic reporting (no PDF export)
- Terminal aesthetic prioritized over UX polish

## SCORING SYSTEM

| Score | Grade | What It Means |
|-------|-------|---------------|
| 80-100 | SECURE | Actually strong password |
| 60-79 | MODERATE | Decent but improvable |
| 40-59 | WEAK | Genuinely problematic |
| 0-39 | CRITICAL | Don't use this password |

## DESIGN PHILOSOPHY

**BRUTALIST = FUNCTIONAL**
- Black text, white background, thick borders
- Monospace fonts (terminal vibes)
- Zero visual fluff or modern UI trends
- Information density over pretty graphics
- Looks like a penetration testing tool

## TEST IT

Try these passwords to see it work:
- `password` → Will show COMPROMISED 
- `admin123` → Will show policy violations
- `MySecureP@ssw0rd2024!` → Should score well
- `123456` → Will be flagged as breached

## MVP STATUS

This is a **working prototype** that demonstrates:
✅ Real password analysis  
✅ Actual breach detection  
✅ Live audit dashboards  
✅ Data-driven reporting  
✅ Brutalist design execution  

**NOT INCLUDED:**
❌ Multi-user support  
❌ Production-scale breach database  
❌ Advanced export features  
❌ Enterprise authentication  

## TECHNICAL NOTES

- **Flask backend** with auto-environment setup
- **SQLite database** for audit logs (no password storage)
- **Vanilla JavaScript** - no frameworks
- **Pure CSS** - brutalist styling only
- **Python 3.6+** compatibility

Run `python main.py` and it just works.