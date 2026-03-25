# Resolve the component name dynamically from the repo root directory name.
# When cloned as "mldsa-native-esp32", the component is "mldsa-native-esp32".
# When used as a submodule named "ml_dsa", it's "ml_dsa".
get_filename_component(_repo_root "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
get_filename_component(ML_DSA_COMPONENT "${_repo_root}" NAME)

idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES ${ML_DSA_COMPONENT} esp_wifi nvs_flash esp_timer
)
