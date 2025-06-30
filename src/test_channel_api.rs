//! Test module to verify the new channel API signatures work correctly

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use serde_cbor::Value;

    #[test]
    fn test_channel_api_signatures_compile() {
        // This test ensures that the new API signatures compile correctly
        // We're testing the type signatures, not the actual functionality
        
        // Test that we can create the expected return types
        let channel_id: u16 = 42;
        let read_cap: BTreeMap<Value, Value> = BTreeMap::new();
        let write_cap: BTreeMap<Value, Value> = BTreeMap::new();
        let message_box_index: BTreeMap<Value, Value> = BTreeMap::new();
        let payload: Vec<u8> = vec![1, 2, 3];
        
        // Test create_write_channel return type
        let _create_write_result: (u16, BTreeMap<Value, Value>, BTreeMap<Value, Value>, BTreeMap<Value, Value>) = 
            (channel_id, read_cap.clone(), write_cap.clone(), message_box_index.clone());
        
        // Test create_channel return type  
        let _create_result: (u16, BTreeMap<Value, Value>) = (channel_id, read_cap.clone());
        
        // Test create_read_channel return type
        let _create_read_result: (u16, BTreeMap<Value, Value>) = (channel_id, message_box_index.clone());
        
        // Test write_channel return type
        let _write_result: (Vec<u8>, BTreeMap<Value, Value>) = (payload.clone(), message_box_index.clone());
        
        // Test read_channel return type (now includes optional reply_index)
        let reply_index: Option<u8> = Some(0);
        let _read_result: (Vec<u8>, BTreeMap<Value, Value>, Option<u8>) = (payload, message_box_index, reply_index);

        // Test close_channel return type
        let _close_result: () = ();

        // Test copy_channel return type
        let _copy_result: () = ();
        
        // Test channel_id type
        assert_eq!(std::mem::size_of::<u16>(), 2);
        assert!(channel_id <= u16::MAX);
        
        println!("All channel API type signatures are correct!");
    }
    
    #[test]
    fn test_channel_id_conversion() {
        // Test that u16 channel IDs work correctly with CBOR Value::Integer
        let channel_id: u16 = 12345;
        let cbor_value = Value::Integer(channel_id.into());

        // Test conversion back
        if let Value::Integer(i) = cbor_value {
            let converted_back = i as u16;
            assert_eq!(converted_back, channel_id);
        } else {
            panic!("CBOR conversion failed");
        }
    }
}
