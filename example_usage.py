# -*- coding: utf-8 -*-
import pprint
import logging

from iar import PolicyScope

from iar import IdentityAccessReport

logging.basicConfig(level=logging.INFO)

if __name__ == '__main__':
    report = IdentityAccessReport()
    report.run(PolicyScope.ALL)
    pprint.pprint(report.overprescribed_policies())
