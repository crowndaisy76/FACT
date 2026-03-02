use binrw::BinRead;

/// NTFS Volume Boot Record (첫 512바이트)
/// #[br(little)] : 윈도우는 리틀 엔디안 방식을 사용한다.
#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct BootSector {
    // 0x00: Jump Instruction (3 bytes) + OEM ID (8 bytes) = 11 bytes skip
    #[br(pad_before = 11)] 
    
    // 0x0B: BPB (BIOS Parameter Block) 시작
    pub bytes_per_sector: u16,      // 섹터당 바이트 (보통 512)
    pub sectors_per_cluster: u8,    // 클러스터당 섹터 (보통 8 -> 4KB)
    
    #[br(pad_before = 7)] // Reserved(2) + Media(1) + Unused(4) skip
    
    pub media_descriptor: u8,
    
    #[br(pad_before = 18)] // Unused fields skip
    
    pub total_sectors: u64,         // 볼륨 전체 크기
    pub mft_lcn: u64,               // $MFT의 시작 클러스터 번호 (Logical Cluster Number)
    pub mft_mirr_lcn: u64,          // $MFTMirr 위치
    
    // ... 나머지 필드는 당장 필요 없으므로 생략
}

impl BootSector {
    /// 클러스터 크기(Byte 단위)를 반환
    pub fn cluster_size(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    /// $MFT가 위치한 실제 바이트 오프셋 계산
    pub fn mft_offset(&self) -> u64 {
        self.mft_lcn * self.cluster_size()
    }
}