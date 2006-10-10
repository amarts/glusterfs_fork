/*
  (C) 2006 Gluster core team <http://www.gluster.org/>
  
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 2 of
  the License, or (at your option) any later version.
    
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
    
  You should have received a copy of the GNU General Public
  License aint64_t with this program; if not, write to the Free
  Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301 USA
*/ 

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "logging.h"

#include "ns.h"
#include "hashfn.h"
#include "logging.h"

static ns_inner_t *global_ns[NS_HASH];

int8_t *
ns_lookup (const int8_t *path)
{
  uint32_t hashval = SuperFastHash ((int8_t *)path, strlen (path));
  ns_inner_t *trav;

  hashval = hashval % NS_HASH;

  trav = global_ns[hashval];
  
  gf_log ("glusterfsd/NS", GF_LOG_CRITICAL, "LOOKUP(%s)", path);
  while (trav) {
    if (!strcmp (trav->path, path))
      break;
    trav = trav->next;
  }

  if (trav) {
    gf_log ("glusterfsd/NS", GF_LOG_CRITICAL, "LOOKUP(%s) -> %s", path, trav->ns);
    return (int8_t *)trav->ns;
  }

  return NULL;
}


int32_t 
ns_update (const int8_t *path, const int8_t *ns)
{
  GF_ERROR_IF_NULL (path);
  GF_ERROR_IF_NULL (ns);

  uint32_t hashval = SuperFastHash ((int8_t *)path, strlen (path));
  ns_inner_t *trav, *prev;

  hashval = hashval % NS_HASH;

  trav = global_ns[hashval];
  prev = NULL;

  while (trav) {
    if (!strcmp (trav->path, path))
      break;
    prev = trav;
    trav = trav->next;
  }

  if (trav) {
    free ((int8_t *)trav->ns);
    trav->ns = ns;
    gf_log ("glusterfsd/NS", GF_LOG_CRITICAL, "UPDATE(%s) (overwrite) -> %s", path, ns);
  } else {
    trav = calloc (1, sizeof (ns_inner_t));
    trav->path = path;
    trav->ns = ns;
    gf_log ("glusterfsd/NS", GF_LOG_CRITICAL, "UPDATE(%s) (new) -> %s", path, ns);
    if (prev)
      prev->next = trav;
    else
      global_ns[hashval] = trav;
  }
  return 0;
}
