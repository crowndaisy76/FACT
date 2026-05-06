use anyhow::{Context, Result, bail};

#[derive(Debug, Clone)]
pub struct RegistryValue {
    pub name: String,
    pub data_type: u32,
    pub data_string: String,
    pub data_raw: Vec<u8>,
    pub is_deleted: bool, // [고도화] 삭제된 값 여부 추적
}

pub struct HiveParser<'a> {
    data: &'a [u8],
}

impl<'a> HiveParser<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < 4096 || &data[0..4] != b"regf" {
            bail!("Invalid Registry Hive signature");
        }
        Ok(Self { data })
    }

    // [고도화] 트랜잭션 로그(.log) In-memory Replay (Dirty Hive 복구용)
    pub fn apply_transaction_logs(hive_data: &mut [u8], log_data: &[u8]) -> Result<()> {
        if log_data.len() < 4096 || &log_data[0..4] != b"regf" {
            bail!("Invalid Log File");
        }
        // 하이브 헤더의 시퀀스 번호와 로그의 시퀀스 번호를 대조하여 더티(Dirty) 상태인지 확인 후,
        // 로그의 Bin 데이터를 원본 hive_data의 해당 오프셋에 직접 덮어씌움 (Zero-Copy 제자리 복구)
        // (실제 Replay 알고리즘 구현부 - 구조상 틀만 잡아둠)
        Ok(())
    }

    #[inline]
    fn abs_offset(&self, offset: u32) -> usize {
        (4096 + offset) as usize
    }

    pub fn get_root_offset(&self) -> u32 {
        u32::from_le_bytes(self.data[0x24..0x28].try_into().unwrap())
    }

    // [고도화] 셀(Cell) 할당 상태 판별: 음수면 사용 중, 양수면 삭제됨(Free)
    fn is_cell_allocated(&self, offset: u32) -> bool {
        let abs_off = self.abs_offset(offset);
        if abs_off + 4 <= self.data.len() {
            let size_val = i32::from_le_bytes(self.data[abs_off..abs_off+4].try_into().unwrap());
            size_val < 0 // 음수일 때 Allocated
        } else {
            false
        }
    }

    pub fn get_key_name(&self, nk_offset: u32) -> String {
        let data_start = self.abs_offset(nk_offset) + 4; 
        if data_start + 76 > self.data.len() || &self.data[data_start..data_start+2] != b"nk" {
            return String::new();
        }
        
        let flags = u16::from_le_bytes([self.data[data_start+0x02], self.data[data_start+0x03]]);
        let name_len = u16::from_le_bytes([self.data[data_start+0x48], self.data[data_start+0x49]]) as usize;
        let name_start = data_start + 0x4C;
        
        if name_start + name_len <= self.data.len() {
            let name_bytes = &self.data[name_start..name_start+name_len];
            let raw = if (flags & 0x0020) != 0 { 
                String::from_utf8_lossy(name_bytes).to_string()
            } else { 
                let u16_name: Vec<u16> = name_bytes.chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&u16_name)
            };
            raw.replace('\0', "").trim().to_string()
        } else {
            String::new()
        }
    }

    pub fn find_child(&self, nk_offset: u32, target_name: &str) -> Option<u32> {
        let data_start = self.abs_offset(nk_offset) + 4;
        if data_start + 76 > self.data.len() { return None; }

        let count = u32::from_le_bytes(self.data[data_start+0x14..data_start+0x18].try_into().unwrap());
        if count == 0 { return None; }

        let list_offset = u32::from_le_bytes(self.data[data_start+0x1C..data_start+0x20].try_into().unwrap());
        if list_offset == 0xFFFFFFFF { return None; }

        self.search_list(list_offset, target_name)
    }

    fn search_list(&self, list_offset: u32, target_name: &str) -> Option<u32> {
        let list_start = self.abs_offset(list_offset) + 4;
        if list_start + 4 > self.data.len() { return None; }

        let sig = &self.data[list_start..list_start+2];
        let count = u16::from_le_bytes([self.data[list_start+2], self.data[list_start+3]]) as usize;
        let elements_start = list_start + 4;

        if sig == b"lf" || sig == b"lh" {
            for i in 0..count {
                let off = elements_start + (i * 8); 
                if off + 4 <= self.data.len() {
                    let nk_off = u32::from_le_bytes(self.data[off..off+4].try_into().unwrap());
                    if self.get_key_name(nk_off).eq_ignore_ascii_case(target_name) {
                        return Some(nk_off);
                    }
                }
            }
        } else if sig == b"li" {
            for i in 0..count {
                let off = elements_start + (i * 4);
                if off + 4 <= self.data.len() {
                    let nk_off = u32::from_le_bytes(self.data[off..off+4].try_into().unwrap());
                    if self.get_key_name(nk_off).eq_ignore_ascii_case(target_name) {
                        return Some(nk_off);
                    }
                }
            }
        } else if sig == b"ri" { 
            for i in 0..count {
                let off = elements_start + (i * 4);
                if off + 4 <= self.data.len() {
                    let child_list_off = u32::from_le_bytes(self.data[off..off+4].try_into().unwrap());
                    if let Some(found) = self.search_list(child_list_off, target_name) {
                        return Some(found);
                    }
                }
            }
        }
        None
    }

    pub fn find_key(&self, path: &str) -> Option<u32> {
        let parts: Vec<&str> = path.split('\\').filter(|p| !p.is_empty()).collect();
        let mut current_offset = self.get_root_offset();

        for part in parts {
            if let Some(child_off) = self.find_child(current_offset, part) {
                current_offset = child_off;
            } else {
                return None;
            }
        }
        Some(current_offset)
    }

    pub fn get_subkeys(&self, nk_offset: u32) -> Vec<u32> {
        let data_start = self.abs_offset(nk_offset) + 4;
        let mut subkeys = Vec::new();
        if data_start + 76 > self.data.len() { return subkeys; }

        let count = u32::from_le_bytes(self.data[data_start+0x14..data_start+0x18].try_into().unwrap());
        if count == 0 { return subkeys; }

        let list_offset = u32::from_le_bytes(self.data[data_start+0x1C..data_start+0x20].try_into().unwrap());
        if list_offset == 0xFFFFFFFF { return subkeys; }

        self.extract_all_subkeys_from_list(list_offset, &mut subkeys);
        subkeys
    }

    fn extract_all_subkeys_from_list(&self, list_offset: u32, subkeys: &mut Vec<u32>) {
        let list_start = self.abs_offset(list_offset) + 4;
        if list_start + 4 > self.data.len() { return; }

        let sig = &self.data[list_start..list_start+2];
        let count = u16::from_le_bytes([self.data[list_start+2], self.data[list_start+3]]) as usize;
        let elements_start = list_start + 4;

        if sig == b"li" {
            for i in 0..count {
                let off = elements_start + (i * 4);
                if off + 4 <= self.data.len() {
                    subkeys.push(u32::from_le_bytes(self.data[off..off+4].try_into().unwrap()));
                }
            }
        } else if sig == b"lh" || sig == b"lf" {
            for i in 0..count {
                let off = elements_start + (i * 8);
                if off + 4 <= self.data.len() {
                    subkeys.push(u32::from_le_bytes(self.data[off..off+4].try_into().unwrap()));
                }
            }
        } else if sig == b"ri" { 
            for i in 0..count {
                let off = elements_start + (i * 4);
                if off + 4 <= self.data.len() {
                    let child_list_off = u32::from_le_bytes(self.data[off..off+4].try_into().unwrap());
                    self.extract_all_subkeys_from_list(child_list_off, subkeys);
                }
            }
        }
    }

    pub fn get_values(&self, nk_offset: u32) -> Vec<RegistryValue> {
        let data_start = self.abs_offset(nk_offset) + 4;
        let mut vals = Vec::new();
        if data_start + 76 > self.data.len() { return vals; }

        let val_count = u32::from_le_bytes(self.data[data_start+0x24..data_start+0x28].try_into().unwrap());
        if val_count == 0 { return vals; }

        let val_list_offset = u32::from_le_bytes(self.data[data_start+0x28..data_start+0x2C].try_into().unwrap());
        if val_list_offset == 0xFFFFFFFF { return vals; }

        let list_start = self.abs_offset(val_list_offset) + 4;
        if list_start + (val_count as usize * 4) > self.data.len() { return vals; }

        for i in 0..val_count as usize {
            let off = list_start + (i * 4);
            let vk_off = u32::from_le_bytes(self.data[off..off+4].try_into().unwrap());
            
            // [고도화] 셀 오프셋을 통해 할당 상태(삭제 여부) 확인
            let is_deleted = !self.is_cell_allocated(vk_off);
            
            let vk_start = self.abs_offset(vk_off) + 4;

            if vk_start + 20 <= self.data.len() && &self.data[vk_start..vk_start+2] == b"vk" {
                let name_len = u16::from_le_bytes([self.data[vk_start+0x02], self.data[vk_start+0x03]]) as usize;
                let mut data_len = u32::from_le_bytes(self.data[vk_start+0x04..vk_start+0x08].try_into().unwrap());
                let data_off = u32::from_le_bytes(self.data[vk_start+0x08..vk_start+0x0C].try_into().unwrap());
                let data_type = u32::from_le_bytes(self.data[vk_start+0x0C..vk_start+0x10].try_into().unwrap());
                let flags = u16::from_le_bytes([self.data[vk_start+0x10], self.data[vk_start+0x11]]);

                let name_start = vk_start + 0x14;
                let raw_name = if name_len == 0 {
                    "(Default)".to_string()
                } else if name_start + name_len <= self.data.len() {
                    if (flags & 0x0001) != 0 { 
                        String::from_utf8_lossy(&self.data[name_start..name_start+name_len]).to_string()
                    } else { 
                        let u16_name: Vec<u16> = self.data[name_start..name_start+name_len].chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                        String::from_utf16_lossy(&u16_name)
                    }
                } else { "Unknown".to_string() };
                
                let name = raw_name.replace('\0', "").trim().to_string();

                let is_inline = (data_len & 0x80000000) != 0;
                data_len &= 0x7FFFFFFF;

                let mut data_raw = Vec::new();
                let data_string = if data_len > 0 {
                    let data_bytes = if is_inline {
                        let end = std::cmp::min(4, data_len) as usize;
                        &self.data[vk_start+0x08 .. vk_start+0x08+end]
                    } else {
                        let d_start = self.abs_offset(data_off) + 4; 
                        if d_start + data_len as usize <= self.data.len() {
                            &self.data[d_start .. d_start + data_len as usize]
                        } else {
                            &[]
                        }
                    };
                    
                    data_raw = data_bytes.to_vec();

                    if data_bytes.is_empty() {
                        "".to_string()
                    } else if data_type == 1 || data_type == 2 || data_type == 7 { 
                        let u16_data: Vec<u16> = data_bytes.chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                        String::from_utf16_lossy(&u16_data).replace('\0', "").trim().to_string()
                    } else if data_type == 4 && data_bytes.len() >= 4 { 
                        let dword = u32::from_le_bytes(data_bytes[0..4].try_into().unwrap());
                        format!("0x{:08X}", dword)
                    } else {
                        format!("BINARY DATA ({} bytes)", data_bytes.len()) 
                    }
                } else { "".to_string() };

                vals.push(RegistryValue { name, data_type, data_string, data_raw, is_deleted });
            }
        }
        vals
    }
    
    // [고도화] 하이브 Bin 영역을 스캔하여 삭제된 모든 키(NK) 추출
    pub fn scan_deleted_keys(&self) -> Vec<u32> {
        let mut deleted_offsets = Vec::new();
        let mut current_offset = 4096; // 첫 번째 Bin 시작점
        
        while current_offset < self.data.len() {
            if current_offset + 32 > self.data.len() { break; }
            
            // hbin 시그니처 확인
            if &self.data[current_offset..current_offset+4] == b"hbin" {
                let bin_size = u32::from_le_bytes(self.data[current_offset+8..current_offset+12].try_into().unwrap()) as usize;
                let mut cell_offset = current_offset + 32;
                let bin_end = current_offset + bin_size;
                
                while cell_offset < bin_end && cell_offset + 4 <= self.data.len() {
                    let cell_size_raw = i32::from_le_bytes(self.data[cell_offset..cell_offset+4].try_into().unwrap());
                    if cell_size_raw == 0 { break; }
                    
                    let is_unallocated = cell_size_raw > 0;
                    let actual_size = cell_size_raw.abs() as usize;
                    
                    if is_unallocated && cell_offset + 6 <= self.data.len() {
                        // 삭제된 셀 중 NK(Name Key) 식별
                        if &self.data[cell_offset+4..cell_offset+6] == b"nk" {
                            // abs_offset 계산을 위한 상대 오프셋으로 변환하여 저장
                            deleted_offsets.push((cell_offset - 4096) as u32);
                        }
                    }
                    cell_offset += actual_size;
                }
                current_offset += bin_size;
            } else {
                break;
            }
        }
        deleted_offsets
    }
}