import Extractor
import argparse
import logging as log


def create_arg_parser():
    parser = argparse.ArgumentParser(description="Description")
    parser.add_argument(
                    "conf_file",
                    help="The extractor configuration file"
                    )
    parser.add_argument(
                    "input_dir",
                    help="Input direcotry containing malwares"
                    )
    parser.add_argument(
                    "-o",
                    "--output-dir",
                    help="Output direcotry",
                    default="./out"
                    )
    parser.add_argument(
                    "-l",
                    "--log-file",
                    help="Logging file",
                    default="MR-extractor.log"
                    )

    return parser


if __name__ == '__main__':
    arg_parser = create_arg_parser()
    args = arg_parser.parse_args()

    # Getting args from the parser
    conf_file = args.conf_file
    in_folder = args.input_dir
    out_folder = args.output_dir
    log_file = args.log_file

    # Making extraction
    log.basicConfig(
        filename=log_file,
        format='[%(levelname)s %(asctime)s] %(message)s',
        datefmt='%m/%d/%Y %H:%M:%S',
        level=log.DEBUG,
    )

    log.info("Starting extraction")
    extractor = Extractor.new(conf_file, in_folder, out_folder)
    extractor.extract_batch()
    log.info("Extraction ended successfully")
