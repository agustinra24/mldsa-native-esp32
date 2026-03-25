get_filename_component(_repo_root "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
get_filename_component(ML_DSA_COMPONENT "${_repo_root}" NAME)

idf_component_register(
    SRCS "test_ml_dsa.c"
    INCLUDE_DIRS "."
    REQUIRES ${ML_DSA_COMPONENT} unity esp_wifi nvs_flash esp_timer
)
