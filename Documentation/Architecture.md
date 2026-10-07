\# Architecture



\## Overview



The Entra ID User Governance Toolkit is structured as a modular PowerShell and Microsoft Graph solution.



The architecture separates:



1\. Discovery

2\. Governance analysis

3\. Interactive review

4\. Remediation

5\. Audit logging

6\. Reporting



\---



\## High-Level Architecture



```text

&#x20;                   Microsoft Entra ID

&#x20;                          |

&#x20;                          |

&#x20;                   Microsoft Graph

&#x20;                          |

&#x20;                          v

&#x20;             +-------------------------+

&#x20;             |  PowerShell Toolkit     |

&#x20;             +-------------------------+

&#x20;                          |

&#x20;         +----------------+----------------+

&#x20;         |                |                |

&#x20;         v                v                v

&#x20;    Discovery         Governance       Graph State

&#x20;                      Analysis          Validation

&#x20;         |                |

&#x20;         +--------+-------+

&#x20;                  |

&#x20;                  v

&#x20;           Review Workflow

&#x20;                  |

&#x20;                  v

&#x20;         Administrator Approval

&#x20;                  |

&#x20;                  v

&#x20;         Controlled Remediation

&#x20;                  |

&#x20;         +--------+--------+

&#x20;         |                 |

&#x20;         v                 v

&#x20;    Audit Logging       Reporting

