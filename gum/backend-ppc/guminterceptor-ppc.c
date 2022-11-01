/*
 * Copyright (C) 2014-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"
#include "gumppcrelocator.h"
#include "gumppcwriter.h"
#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>
#include <unistd.h>

/*
 * This constant represents the size of the hook assembly sequence which
 * is to be written over the prologue of the intercepted function. This
 * is a minimalist stub which simply vectors to the larger trampoline which
 * stores the CPU context and transitions to C code passing the necessary
 * landmarks.
 */
#if GLIB_SIZEOF_VOID_P == 8
# define GUM_HOOK_SIZE 28
#else
# define GUM_HOOK_SIZE 16
#endif

#define USE_SCRATCH_REGISTER 0


#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof(GumCpuContext))

#define GUM_FCDATA(context) \
    ((GumPpcFunctionContextData *) (context)->backend_data.storage)

typedef struct _GumPpcFunctionContextData GumPpcFunctionContextData;

struct _GumInterceptorBackend
{
  GumCodeAllocator * allocator;

  GumPpcWriter writer;
  GumPpcRelocator relocator;

  GumCodeSlice * enter_thunk;
  GumCodeSlice * leave_thunk;
};

struct _GumPpcFunctionContextData
{
  guint redirect_code_size;
  ppc_reg scratch_reg;
};

G_STATIC_ASSERT (sizeof (GumPpcFunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_enter_thunk (GumPpcWriter * aw);
static void gum_emit_leave_thunk (GumPpcWriter * aw);

static void gum_emit_prolog (GumPpcWriter * aw);
static void gum_emit_epilog (GumPpcWriter * aw);

GumInterceptorBackend *
_gum_interceptor_backend_create (GRecMutex * mutex,
                                 GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);
  backend->allocator = allocator;

  gum_ppc_writer_init (&backend->writer, NULL);
  gum_ppc_relocator_init (&backend->relocator, NULL, &backend->writer);

  gum_interceptor_backend_create_thunks (backend);

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_ppc_relocator_clear (&backend->relocator);
  gum_ppc_writer_clear (&backend->writer);

  g_slice_free (GumInterceptorBackend, backend);
}

gboolean
_gum_interceptor_backend_claim_grafted_trampoline (GumInterceptorBackend * self,
                                                   GumFunctionContext * ctx)
{
  return FALSE;
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumPpcFunctionContextData * data = GUM_FCDATA (ctx);

  data->redirect_code_size = GUM_HOOK_SIZE;

  ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);

  if (!gum_ppc_relocator_can_relocate (ctx->function_address,
        data->redirect_code_size, NULL, &data->scratch_reg))
  {
    /* Not enough space for hook */
    gum_code_slice_unref (ctx->trampoline_slice); /* free slice */
    ctx->trampoline_slice = NULL;
    return FALSE;
  }

  /* Check if a scratch register was found */
  if (data->scratch_reg == PPC_REG_INVALID)
    return FALSE;

  return TRUE;
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumPpcWriter * cw = &self->writer;
  GumPpcRelocator * rl = &self->relocator;
  gpointer function_address = ctx->function_address;
  GumPpcFunctionContextData * data = GUM_FCDATA (ctx);
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_ppc_writer_reset (cw, ctx->trampoline_slice->data);

  /* On PPC the calling convention is that r3- r10, thus 8 arguments, are 
   * passed in registers, but they can also be passed on the stack. Hence r11
   * is our first available register, otherwise we will start clobbering 
   * function parameters. However, most volatile registers also have predefined
   * funtions. r0 appears to be a good candidate for storing temporary data. 
   * TODO: To be verified.
   */

  /* On_enter trampoline:
   * LI32 R0, enter_thunk     # Load enter_thunk address (LIS, ORI)
   * MTCTR R0                 # Move it to CTR
   * LI32 R0, ctx             # Load ctx address as param
   * BCTR                     # Branch to CTR -> jump to enter_thunk(ctx)
   */
  ctx->on_enter_trampoline = gum_ppc_writer_cur (cw);
  gum_ppc_writer_put_li32_reg_address (cw, PPC_REG_R0, GUM_ADDRESS (self->enter_thunk->data));
  gum_ppc_writer_put_mtctr_reg (cw, PPC_REG_R0);
  gum_ppc_writer_put_li32_reg_address (cw, PPC_REG_R0, GUM_ADDRESS (ctx));
  gum_ppc_writer_put_bctr_offset (cw);

  /* On_leave trampoline:
   * LI32 R0, leave_thunk     # Load leave_thunk address (LIS, ORI)
   * MTCTR R0                 # Move it to CTR
   * LI32 R0, ctx             # Load ctx address as param (LIS, ORI)
   * BCTR                     # Branch to CTR -> jump to leave_thunk(ctx)
   */
  ctx->on_leave_trampoline = gum_ppc_writer_cur (cw);
  gum_ppc_writer_put_li32_reg_address (cw, PPC_REG_R0, GUM_ADDRESS (self->leave_thunk->data));
  gum_ppc_writer_put_mtctr_reg (cw, PPC_REG_R0);
  gum_ppc_writer_put_li32_reg_address (cw, PPC_REG_R0, GUM_ADDRESS (ctx));
  gum_ppc_writer_put_bctr_offset (cw);

  gum_ppc_writer_flush (cw);
  g_assert (gum_ppc_writer_offset (cw) <= ctx->trampoline_slice->size);

  /* On_invoke trampoline:
   * Populate with instructions from the original function as they will be 
   * overwritten by the redirection hook).
   * Then jump back to resume the original function. 
   * TODO: Load CTR before relocated code?
   */
  ctx->on_invoke_trampoline = gum_ppc_writer_cur (cw);
  gum_ppc_relocator_reset (rl, function_address, cw);
  do
  {
    reloc_bytes = gum_ppc_relocator_read_one (rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < data->redirect_code_size);
  gum_ppc_relocator_write_all (rl);

  if (!gum_ppc_relocator_eoi (rl))
  {
    GumAddress resume_at;
    resume_at = GUM_ADDRESS (function_address) + reloc_bytes;

#if USE_SCRATCH_REGISTER == 1
    /* LI32 Rx, resume_at       # Load resume_at address (LIS, ORI)
     * MTCTR Rx                 # Move it to CTR
     * BCTR                     # Branch to CTR -> jump to resume_at
     * (Use detected scratch register Rx to prevent register clobbering)
     */
    gum_ppc_writer_put_li32_reg_address (cw, data->scratch_reg, resume_at);
    gum_ppc_writer_put_mtctr_reg (cw, data->scratch_reg);
    gum_ppc_writer_put_bctr_offset (cw);
#else
    /* PUSH R0                  # Push temp register
     * LI32 R0, resume_at       # Load resume_at address (LIS, ORI)
     * MTCTR R0                 # Move it to CTR
     * POP R0                   # Pop temp register
     * BCTR                     # Branch to CTR -> jump to resume_at
     * (Save R0 on stack to prevent register clobbering. Is stack valid here?)
     */
    /* PUSH */
    gum_ppc_writer_put_li32_reg_address (cw, PPC_REG_R0, resume_at);
    gum_ppc_writer_put_mtctr_reg (cw, PPC_REG_R0);
    /* POP */
    gum_ppc_writer_put_bctr_offset (cw);
#endif
  }

  gum_ppc_writer_flush (cw);
  g_assert (gum_ppc_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  gum_code_slice_unref (ctx->trampoline_slice);
  gum_code_deflector_unref (ctx->trampoline_deflector);
  ctx->trampoline_slice = NULL;
  ctx->trampoline_deflector = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumPpcWriter * cw = &self->writer;
  GumPpcFunctionContextData * data = GUM_FCDATA (ctx);
  GumAddress on_enter = GUM_ADDRESS (ctx->on_enter_trampoline);

  gum_ppc_writer_reset (cw, prologue);
  cw->pc = GUM_ADDRESS (ctx->function_address);

  switch (data->redirect_code_size)
  {
    case 8:
      /* TODO: support near relative jump B ? */
      g_assert_not_reached ();
      break;
    case GUM_HOOK_SIZE:
#if GLIB_SIZEOF_VOID_P == 8
      /* PPC64: TODO */
      g_assert_not_reached ();
#else
      /* Load imm32 into reg, copy reg to CTR, branch to CTR */
      gum_ppc_writer_put_li32_reg_address (cw, PPC_REG_R0, on_enter);
      gum_ppc_writer_put_mtctr_reg (cw, PPC_REG_R0);
      gum_ppc_writer_put_bctr_offset (cw);
#endif
      break;
    default:
      g_assert_not_reached ();
  }


  gum_ppc_writer_flush (cw);
  g_assert (gum_ppc_writer_offset (cw) <= data->redirect_code_size);
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer prologue)
{
  gum_memcpy (prologue, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_backend_get_function_address (GumFunctionContext * ctx)
{
  return ctx->function_address;
}

gpointer
_gum_interceptor_backend_resolve_redirect (GumInterceptorBackend * self,
                                           gpointer address)
{
  /* TODO: implement resolve redirect */
  return NULL;
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumPpcWriter * cw = &self->writer;

  self->enter_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_ppc_writer_reset (cw, self->enter_thunk->data);
  gum_emit_enter_thunk (cw);
  gum_ppc_writer_flush (cw);
  g_assert (gum_ppc_writer_offset (cw) <= self->enter_thunk->size);

  self->leave_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_ppc_writer_reset (cw, self->leave_thunk->data);
  gum_emit_leave_thunk (cw);
  gum_ppc_writer_flush (cw);
  g_assert (gum_ppc_writer_offset (cw) <= self->leave_thunk->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_unref (self->leave_thunk);

  gum_code_slice_unref (self->enter_thunk);
}

static void
gum_emit_enter_thunk (GumPpcWriter * cw)
{
  gum_emit_prolog (cw);

  /* TODO */
  /*
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A1, MIPS_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A2, MIPS_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, ra));
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A3, MIPS_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, PPC_REG_R0,
      GUM_ARG_REGISTER, MIPS_REG_A1,  // cpu_context
      GUM_ARG_REGISTER, MIPS_REG_A2,  // return_address
      GUM_ARG_REGISTER, MIPS_REG_A3); // next_hop
  */
  gum_emit_epilog (cw);
}

static void
gum_emit_leave_thunk (GumPpcWriter * cw)
{
  gum_emit_prolog (cw);

  /* TODO */
  /*
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A1, MIPS_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A2, MIPS_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, MIPS_REG_T0,
      GUM_ARG_REGISTER, MIPS_REG_A1,  // cpu_context
      GUM_ARG_REGISTER, MIPS_REG_A2); // next_hop
  */
  gum_emit_epilog (cw);
}

static void
gum_emit_prolog (GumPpcWriter * cw)
{
  /*
   * Set up our stack frame:
   *
   * [next_hop]
   * [cpu_context]
   */

  /* TODO */
  /*
  gum_mips_writer_put_push_reg (cw, MIPS_REG_ZERO);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_K1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_K0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_S7);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S6);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S5);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S4);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S3);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S2);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_T9);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T8);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T7);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T6);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T5);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T4);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T3);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T2);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_A3);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_A2);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_A1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_A0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_V1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_AT);

  gum_mips_writer_put_mflo_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_mfhi_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_RA);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_FP);
  */
  /*
   * SP
   *
   * Here we are calculating the original stack pointer (before we stored) all
   * the context above and saving it to the stack so that it can be read as part
   * of the CpuContext structure.
   */
  /*
#if GLIB_SIZEOF_VOID_P == 8
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_V0, MIPS_REG_SP,
      8 + (30 * 8));
#else
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_V0, MIPS_REG_SP,
      4 + (30 * 4));
#endif
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_GP);
  */
  /* Dummy PC */
  /*
  gum_mips_writer_put_push_reg (cw, MIPS_REG_ZERO);
  */
}

static void
gum_emit_epilog (GumPpcWriter * cw)
{
  /* TODO */
  /* Dummy PC */
  /*
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_GP);
  */
  /* Dummy SP */
  /*
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_FP);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_RA);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_mthi_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_mtlo_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_AT);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V1);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A1);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A2);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A3);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T1);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T2);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T3);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T4);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T5);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T6);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T7);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T8);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T9);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S1);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S2);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S3);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S4);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S5);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S6);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S7);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_K0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_K1);
  */
  /*
   * Pop and jump to the next_hop.
   *
   * This needs to be via t9 so that PIC code works.
   */
  /*
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T9);
  gum_mips_writer_put_jr_reg (cw, MIPS_REG_T9);
  */
}
