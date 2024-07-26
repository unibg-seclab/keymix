#ifndef MIXCTR_H
#define MIXCTR_H

#include "types.h"

mixctrpass_impl_t get_mixctr_impl(mixctrpass_t name);

mixctrpass_t mixctr_from_str(char *name);

#endif
