if(CMAKE_GENERATOR STREQUAL "Ninja")
  set(NB_DEPENDENCY_PROBE "${CMAKE_BINARY_DIR}/CMakeFiles/NativeBoxDependencies")
  file(MAKE_DIRECTORY "${NB_DEPENDENCY_PROBE}")
  file(WRITE "${NB_DEPENDENCY_PROBE}/nb_dependency_probe.h" "\n")
  file(WRITE "${NB_DEPENDENCY_PROBE}/probe.c" "#include \"nb_dependency_probe.h\"\nint nativebox_dependency_probe(void) { return 0; }\n")
  execute_process(COMMAND "${CMAKE_CXX_COMPILER}" /nologo /showIncludes /c probe.c
    WORKING_DIRECTORY "${NB_DEPENDENCY_PROBE}"
    OUTPUT_VARIABLE NB_DEPENDENCY_OUTPUT ERROR_VARIABLE NB_DEPENDENCY_ERROR
    RESULT_VARIABLE NB_DEPENDENCY_RESULT ENCODING NONE)
  if(NOT NB_DEPENDENCY_RESULT EQUAL 0 OR
      NOT NB_DEPENDENCY_OUTPUT MATCHES "(^|\n)([^:\n][^:\n]+:[^:\n]*[^: \n][^: \n]:?[ \t]+)([A-Za-z]:\\\\|\\./|\\.\\\\|/)")
    message(FATAL_ERROR "Cannot determine the actual MSVC dependency prefix: ${NB_DEPENDENCY_ERROR}")
  endif()
  set(CMAKE_CL_SHOWINCLUDES_PREFIX "${CMAKE_MATCH_2}")
  set(CMAKE_CXX_CL_SHOWINCLUDES_PREFIX "${CMAKE_MATCH_2}")
endif()
