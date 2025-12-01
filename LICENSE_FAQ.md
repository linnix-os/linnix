# Licensing FAQ

Linnix uses a split licensing model to balance open collaboration with sustainable business practices.

## The Short Version

*   **Using Linnix?** It's free and open source. You can run it at work, at home, or in production.
*   **Building a SaaS competitor?** You need to open-source your modifications or buy a commercial license.

## Component Licenses

| Component | License | Why? |
| :--- | :--- | :--- |
| **Agent (`cognitod`)** | **AGPL-3.0** | This is the "brain" of Linnix. If you modify it to sell a service, you must share your changes. |
| **eBPF Collector** | **GPL-2.0 OR MIT** | The low-level kernel probes. Dual-licensed for flexibility (eBPF programs must be GPL-compatible for kernel loading). |
| **Dashboard / CLI** | **AGPL-3.0** | User interfaces. |

## Q: Can I use Linnix at my company?
**Yes.** You can install, run, and use Linnix internally at your company without any legal issues. The AGPL only affects you if you *distribute* the software or offer it as a service to *others*.

## Q: What if I need a commercial license?
If your legal team has a blanket ban on AGPL, or if you want to embed Linnix into a proprietary product, please contact us for a commercial license.
