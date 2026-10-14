"""Entry point for the CIS Security Audit desktop application."""
from gui import CISAuditApp


def main():
    app = CISAuditApp()
    app.mainloop()


if __name__ == "__main__":
    main()
