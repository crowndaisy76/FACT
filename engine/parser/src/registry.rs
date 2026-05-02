use anyhow::{Result, bail};

#[derive(Debug, Clone)]
pub struct RegistryValue {
    pub name: String,
    pub data_type: u32,
    pub data_string: String,
    pub data_raw: Vec<u8>,
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

    fn abs_offset(&self, offset: u32) -> usize {
        (4096 + offset) as usize
    }

    pub fn get_root_offset(&self) -> u32 {
        u32::from_le_bytes(self.data[0x24..0x28].try_into().unwrap())
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

    /// [Industry Standard] 특정 노드(nk) 하위에서 원하는 이름(target_name)을 가진 자식만 초고속으로 찾아낸다.
    pub fn find_child(&self, nk_offset: u32, target_name: &str) -> Option<u32> {
        let data_start = self.abs_offset(nk_offset) + 4;
        if data_start + 76 > self.data.len() { return None; }

        let count = u32::from_le_bytes(self.data[data_start+0x14..data_start+0x18].try_into().unwrap());
        if count == 0 { return None; }

        let list_offset = u32::from_le_bytes(self.data[data_start+0x1C..data_start+0x20].try_into().unwrap());
        if list_offset == 0xFFFFFFFF { return None; }

        self.search_list(list_offset, target_name)
    }

    /// 리스트(li, ri, lh, lf) 내부를 직접 재귀 탐색하여 타겟을 사냥한다.
    fn search_list(&self, list_offset: u32, target_name: &str) -> Option<u32> {
        let list_start = self.abs_offset(list_offset) + 4;
        if list_start + 4 > self.data.len() { return None; }

        let sig = &self.data[list_start..list_start+2];
        let count = u16::from_le_bytes([self.data[list_start+2], self.data[list_start+3]]) as usize;
        let elements_start = list_start + 4;

        if sig == b"lf" || sig == b"lh" {
            for i in 0..count {
                let off = elements_start + (i * 8); // lf/lh는 엘리먼트가 8바이트 (앞 4바이트가 오프셋)
                if off + 4 <= self.data.len() {
                    let nk_off = u32::from_le_bytes(self.data[off..off+4].try_into().unwrap());
                    if self.get_key_name(nk_off).eq_ignore_ascii_case(target_name) {
                        return Some(nk_off);
                    }
                }
            }
        } else if sig == b"li" {
            for i in 0..count {
                let off = elements_start + (i * 4); // li는 엘리먼트가 4바이트
                if off + 4 <= self.data.len() {
                    let nk_off = u32::from_le_bytes(self.data[off..off+4].try_into().unwrap());
                    if self.get_key_name(nk_off).eq_ignore_ascii_case(target_name) {
                        return Some(nk_off);
                    }
                }
            }
        } else if sig == b"ri" { // 거대 트리의 핵심: Root Index 재귀 탐색
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

    /// 전체 경로를 입력받아 계층적으로(Tree-Walking) 최종 키 오프셋을 찾는다.
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
                    } else if data_type == 1 || data_type == 2 || data_type == 7 { // REG_SZ 계열
                        let u16_data: Vec<u16> = data_bytes.chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                        String::from_utf16_lossy(&u16_data).replace('\0', "").trim().to_string()
                    } else if data_type == 4 && data_bytes.len() >= 4 { // REG_DWORD
                        let dword = u32::from_le_bytes(data_bytes[0..4].try_into().unwrap());
                        format!("0x{:08X}", dword)
                    } else {
                        format!("BINARY DATA ({} bytes)", data_bytes.len()) 
                    }
                } else { "".to_string() };

                vals.push(RegistryValue { name, data_type, data_string, data_raw });
            }
        }
        vals
    }
}