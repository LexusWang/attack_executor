import configparser

def load_config(config_file_path="config.ini"):
    config = configparser.ConfigParser()
    config.read(config_file_path)

    debug = config["DEFAULT"].getboolean("debug")
    log_path = config["DEFAULT"].get("log_path")
    
    sliver = config["sliver"].get("client_config_file")

    enable_new_feature = config["feature_flags"].getboolean("enable_new_feature")

    return config

if __name__ == "__main__":
    config_dict = load_config()
    print(config_dict)
