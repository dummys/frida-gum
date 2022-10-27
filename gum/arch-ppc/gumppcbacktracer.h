/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PPC_BACKTRACER_H__
#define __GUM_PPC_BACKTRACER_H__

#include <gum/gumbacktracer.h>

G_BEGIN_DECLS

#define GUM_TYPE_PPC_BACKTRACER (gum_ppc_backtracer_get_type ())
GUM_DECLARE_FINAL_TYPE (GumPpcBacktracer, gum_ppc_backtracer, GUM,
                        PPC_BACKTRACER, GObject)

GUM_API GumBacktracer * gum_ppc_backtracer_new (void);

G_END_DECLS

#endif
