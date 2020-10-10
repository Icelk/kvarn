use crate::char_const::*;
use crate::{read_file, FsCache};

// #[cfg(feature = "php")]
pub use php::handle_php as php;
pub use templates::handle_template as template;

// #[cfg(feature = "php")]
pub mod php {
  use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
  use std::path::PathBuf;
  use std::{
    fs::File,
    io::{self, prelude::*},
  };

  #[allow(unused_variables)]
  pub fn handle_php<W: Write>(
    socket: &mut W,
    request: &[u8],
    path: &PathBuf,
  ) -> Result<(), io::Error> {
    unimplemented!();

    // Take the thread name and make a file of that instead. Try the line for line mode instead.
    let mut temp = File::create("temp.php")?;
    let mut file = File::open(path)?;
    let mut buffer = [0; 4096];
    let mut first = true;
    loop {
      let read = file.read(&mut buffer)?;
      if read == 0 {
        break;
      }
      if first {
        let read_till = {
          let mut out = 0;
          for byte in buffer.iter() {
            out += 1;
            if *byte == 10 {
              break;
            }
          }
          out
        };
        println!("Discard first {}", read_till);
        temp.write_all(&mut &buffer[read_till..read])?;
        first = false;
      } else {
        temp.write_all(&mut buffer[..read])?;
      }
    }

    let mut php =
      match TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6633))) {
        Err(err) => {
          panic!("Failed to get PHP: {:?}", err);
        }
        Ok(socket) => socket,
      };

    todo!("Change path to /temp.php! Or implement interpreter!");
    php.write_all(request)?;
    loop {
      let mut buffer = [0; 4096];
      let read = php.read(&mut buffer)?;
      if read == 0 {
        break;
      }
      socket.write_all(&mut buffer[0..read])?;
    }

    Ok(())
  }
}

pub mod templates {
  use super::*;
  use std::path::PathBuf;
  use std::sync::Arc;
  use std::{collections::HashMap, str};

  pub fn handle_template(arguments: &[&[u8]], file: &[u8], fs_cache: &mut FsCache) -> Vec<u8> {
    // Get files
    let template_files = get_files(arguments, fs_cache);

    // Check for templates
    let templates = extract_templates(&template_files);

    #[derive(Eq, PartialEq)]
    enum Stage {
      ExtensionDefinition,
      Text,
      Placeholder,
    };

    let mut response = Vec::new();

    let mut stage = Stage::ExtensionDefinition;
    let mut placeholder_start = 0;
    let mut escaped = 0;
    for (position, byte) in file.iter().enumerate() {
      let is_escape = *byte == ESCAPE;

      match stage {
        // If in extension definition stage, check when it ends
        Stage::ExtensionDefinition => {
          if *byte == LF {
            stage = Stage::Text;
          }
        }
        // If in text stage, check for left bracket. Then set the variables for starting identifying the placeholder for template
        // Push the current byte to response, if not start of placeholder
        Stage::Text if (escaped == 0 && !is_escape) || escaped == 1 => {
          if *byte == L_SQ_BRACKET && escaped != 1 {
            placeholder_start = position;
            stage = Stage::Placeholder;
          } else {
            response.push(*byte);
          }
        }
        Stage::Placeholder if escaped != 1 => {
          // If placeholder closed
          if *byte == R_SQ_BRACKET {
            // Check if name is longer than empty
            if position.checked_sub(placeholder_start + 2).is_some() {
              // Good; we have UTF-8
              if let Ok(key) = str::from_utf8(&file[placeholder_start + 1..position]) {
                // If it is a valid template?
                if let Some(template) = templates.get(key) {
                  // Push template byte-slice to the response
                  for byte in *template {
                    response.push(*byte);
                  }
                }
              }
            }
            // Set stage to accept new text
            stage = Stage::Text;
          }
        }
        // Else, it's a escaping character!
        _ => {}
      }

      // Do we escape?
      if is_escape {
        escaped += 1;
        if escaped == 2 {
          escaped = 0;
        }
      } else {
        escaped = 0;
      }
    }
    response
  }
  fn get_files(arguments: &[&[u8]], fs_cache: &mut FsCache) -> Vec<Arc<Vec<u8>>> {
    let template_dir = PathBuf::from("templates");

    let mut files = Vec::with_capacity(arguments.len() - 1);
    for template in arguments.iter().skip(1).rev() {
      if let Ok(template) = str::from_utf8(template) {
        if let Some(file) = read_file(&template_dir.join(template), fs_cache) {
          files.push(file);
        };
      }
    }
    files
  }
  fn extract_templates(files: &[Arc<Vec<u8>>]) -> HashMap<&str, &[u8]> {
    let mut templates = HashMap::new();
    for file in files {
      let mut last_was_lf = true;
      let mut escape = false;
      let mut name_start = 0;
      let mut name_end = 0usize;
      let mut newline_size = 1;
      for (position, byte) in file.iter().enumerate() {
        // Ignore all CR characters
        if *byte == CR {
          newline_size = 2;
          continue;
        }
        // If previous char was \, escape!
        // New template, process previous!
        if !escape && last_was_lf && *byte == L_SQ_BRACKET {
          // If name is longer than empty
          if name_end.checked_sub(name_start + 2).is_some() {
            // Check if we have a valid UTF-8 string
            if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
              // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
              let add_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
                newline_size
              } else {
                if file.get(name_end) == Some(&SPACE) {
                  1
                } else {
                  0
                }
              };
              // Then insert template; name we got from previous step, then bytes from where the previous template definition ended, then our current position, just before the start of the next template
              // Returns a byte-slice of the file
              templates.insert(
                name,
                &file[name_end + add_after_name..position - newline_size],
              );
            }
          }
          // Set start of template name to now
          name_start = position;
        }
        if *byte == R_SQ_BRACKET {
          name_end = position + 1;
        }

        last_was_lf = *byte == LF;
        escape = *byte == ESCAPE;
      }
      // Because we add the definitions in the start of the new one, check for last in the end of file
      if name_end.checked_sub(name_start + 2).is_some() {
        if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
          // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
          let add_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
            newline_size
          } else {
            if file.get(name_end) == Some(&SPACE) {
              1
            } else {
              0
            }
          };
          templates.insert(
            name,
            &file[name_end + add_after_name..file.len() - newline_size],
          );
        }
      }
    }
    templates
  }
}
