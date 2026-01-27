import argparse
import aegiscli.core.logger as logger


def main():
    parser = argparse.ArgumentParser(
        prog="aegiscli",
        description="AegisCLI - modular recon framework"
    )
    global_parser = argparse.ArgumentParser(add_help=False)
    global_parser.add_argument("--log", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    whois_parser = subparsers.add_parser("whois", parents=[global_parser])
    whois_parser.add_argument("target")

    args = parser.parse_args()
    if args.log:
        logger.start_log()

    try:
        if args.command == "whois":
            import aegiscli.tools.profiler.whois as whois
            script = whois.Whois(settings=None, advanced=False, target=args.target)
            script.domain_info()

    except Exception as e:
        logger.log(f"[ERROR]: {e}")

    finally:
        if args.log:
            logger.stop_log()


if __name__ == "__main__":
    main()
