/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef XMLSEC_VERSION_H
#define XMLSEC_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief The library version string in the format "$major_number.$minor_number.$sub_minor_number".
 */
#define XMLSEC_VERSION          "1.3.14"

/**
 * @brief The library major version number.
 */
#define XMLSEC_VERSION_MAJOR    1

/**
 * @brief The library minor version number.
 */
#define XMLSEC_VERSION_MINOR    3

/**
 * @brief The library sub-minor version number.
 */
#define XMLSEC_VERSION_SUBMINOR 14

/**
 * @brief The library version info string in the libtool "$current:$revision:$age" format,
 *         where current = 10000*major + 100*minor + subminor.
 */
#define XMLSEC_VERSION_INFO     "10314:0:0"

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_VERSION_H */
