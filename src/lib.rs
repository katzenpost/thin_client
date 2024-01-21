// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

pub mod error;

use libc;
use std::{io::self, mem};
use core::mem::MaybeUninit;
use rand::RngCore;

use socket2::{Domain, SockAddr, Socket, Type};
use cbor::{Decoder, Encoder};

use self::error::ThinClientError;


fn abstract_socket_addr(socket_name: &[u8]) -> Result<SockAddr, ThinClientError> {
    let mut addr = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };
    addr.sun_path[0] = 0; // First byte as 0 for abstract namespace
    for (dst, src) in addr.sun_path[1..socket_name.len() + 1].iter_mut().zip(socket_name.iter()) {
        *dst = *src as libc::c_char;
    }
    let addr_len = mem::size_of::<libc::sockaddr_un>() as u32;
    let (_, sock_addr) = unsafe {
	SockAddr::try_init(|addr_storage, len| {
            if addr_len > *len as u32 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Address length exceeds storage size"));
            }

            std::ptr::copy_nonoverlapping(&addr as *const _ as *const u8, addr_storage as *mut u8, addr_len as usize);
            *len = addr_len as libc::socklen_t;
            Ok(())
	})
    }?;
    Ok(sock_addr)
}

pub struct ThinClient {
    client_socket: Socket,
}

impl ThinClient {

    pub fn new() -> Result<Self, ThinClientError> {
        let mut client_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut client_id);
        let client_socket_string = client_id.iter().map(|byte| format!("{:02x}", byte)).collect::<String>();
        let formatted_socket_name = format!("katzenpost_golang_thin_client_{}", client_socket_string);
        let client_socket_name = formatted_socket_name.as_bytes();
        let client_addr = abstract_socket_addr(client_socket_name)?;
        let client_socket = Socket::new(Domain::UNIX, Type::SEQPACKET, None)?;

	client_socket.bind(&client_addr)?;
	
	return Ok(ThinClient{
	    client_socket: client_socket,
	});
    }
    
    pub fn connect(&mut self) -> Result<(), ThinClientError> {
	let server_socket_string = "katzenpost";
	let server_socket_name = server_socket_string.as_bytes();
	let server_addr = abstract_socket_addr(server_socket_name)?;

	self.client_socket.connect(&server_addr)?;
	
        Ok(())
    }

    pub fn start_worker(&mut self) -> Result<(), ThinClientError> {
	let mut buf: [MaybeUninit<u8>; 10240] = unsafe { MaybeUninit::uninit().assume_init() };
	let size_read = self.client_socket.recv(&mut buf)?;
	
        let mut data_vec = Vec::with_capacity(size_read);
        for i in 0..size_read {
            unsafe {
                data_vec.push(buf[i].assume_init());
            }
        }

	let mut d = Decoder::from_bytes(data_vec);
	let items: Vec<(String, i32)> = d.decode().collect::<Result<_, _>>().unwrap();
	
	Ok(())
    }
}
