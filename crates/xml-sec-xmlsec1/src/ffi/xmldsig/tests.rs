use super::*;

#[test]
fn status_and_failure_strings_are_libxmlsec1s() {
    // The strings applications print and compare.
    assert_eq!(status_string(STATUS_SUCCEEDED), c"OK");
    assert_eq!(status_string(STATUS_INVALID), c"FAILED");
    assert_eq!(status_string(STATUS_UNKNOWN), c"ERROR");
    assert_eq!(status_string(42), c"ERROR");
    assert_eq!(failure_string(FAILURE_REFERENCE), c"REFERENCE");
    assert_eq!(failure_string(FAILURE_SIGNATURE), c"SIGNATURE");
    assert_eq!(failure_string(FAILURE_KEY_NOT_FOUND), c"KEY-NOT-FOUND");
    assert_eq!(failure_string(FAILURE_UNKNOWN), c"UNKNOWN");
    assert_eq!(failure_string(-1), c"UNKNOWN");
}

#[test]
fn a_created_context_has_libxmlsec1s_defaults_and_finalizes_to_zero() {
    // SAFETY: a context created and destroyed here; a stack context
    // initialized and finalized here.
    unsafe {
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        assert!(!ctx.is_null());
        let context = &*ctx;
        assert_eq!(context.enabled_reference_uris, REFERENCE_URIS_DEFAULT);
        assert_eq!(context.key_info_read_ctx.mode, MODE_READ);
        assert_eq!(context.key_info_write_ctx.mode, MODE_WRITE);
        assert_eq!(context.key_info_write_ctx.key_req.key_type, TYPE_PUBLIC);
        assert_eq!(context.status, STATUS_UNKNOWN);
        assert!(xmlSecDSigCtxGetPreSignBuffer(ctx).is_null());
        xmlSecDSigCtxDestroy(ctx);

        let mut stack = std::mem::MaybeUninit::<XmlSecDSigCtx>::uninit();
        assert_eq!(
            xmlSecDSigCtxInitialize(stack.as_mut_ptr(), std::ptr::null_mut()),
            0
        );
        xmlSecDSigCtxFinalize(stack.as_mut_ptr());
        let bytes =
            std::slice::from_raw_parts(stack.as_ptr().cast::<u8>(), size_of::<XmlSecDSigCtx>());
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn enabling_transforms_needs_a_klass_and_a_fresh_context() {
    // SAFETY: a context created and destroyed here; the klass is static.
    unsafe {
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        let klass = super::super::transforms::builtin::xmlSecTransformBase64GetKlass();
        assert_eq!(xmlSecDSigCtxEnableReferenceTransform(ctx, klass), 0);
        assert_eq!(xmlSecDSigCtxEnableSignatureTransform(ctx, klass), 0);
        assert_eq!(
            xmlSecDSigCtxEnableReferenceTransform(ctx, std::ptr::null()),
            -1
        );
        // A context holding a result has run: its transforms are fixed.
        let mut buffer = std::mem::zeroed::<XmlSecBuffer>();
        (*ctx).result = &raw mut buffer;
        assert_eq!(xmlSecDSigCtxEnableReferenceTransform(ctx, klass), -1);
        (*ctx).result = std::ptr::null_mut();
        xmlSecDSigCtxDestroy(ctx);
    }
}

#[test]
fn a_reference_context_inherits_the_signature_contexts_settings() {
    // SAFETY: contexts created and destroyed here.
    unsafe {
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).flags = FLAGS_USE_VISA3D_HACK | FLAGS_ALLOW_EMPTY_INPUT_DSIG;
        (*ctx).enabled_reference_uris = 0x0004;
        let mut marker = 7_u8;
        (*ctx).user_data = (&raw mut marker).cast();
        let reference = xmlSecDSigReferenceCtxCreate(ctx, ORIGIN_MANIFEST);
        assert!(!reference.is_null());
        let context = &*reference;
        assert_eq!(context.origin, ORIGIN_MANIFEST);
        assert_eq!(context.transform_ctx.enabled_uris, 0x0004);
        assert_eq!(context.transform_ctx.user_data, (&raw mut marker).cast());
        assert_eq!(
            context.transform_ctx.flags,
            TRANSFORMCTX_VISA3D | FLAGS_ALLOW_EMPTY_INPUT
        );
        assert!(xmlSecDSigReferenceCtxGetPreDigestBuffer(reference).is_null());
        xmlSecDSigReferenceCtxDestroy(reference);
        xmlSecDSigCtxDestroy(ctx);
    }
}
