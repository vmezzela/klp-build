import os
import sys

from klpbuild.cmd import main_func

SUSE_CA_CERT = "/etc/ssl/certs/SUSE_Trust_Root.pem"


def main():
    if os.path.exists(SUSE_CA_CERT):
        os.environ["REQUESTS_CA_BUNDLE"] = SUSE_CA_CERT

    main_func(sys.argv[1:])


if __name__ == "__main__":
    main()
