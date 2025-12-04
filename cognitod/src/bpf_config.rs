use anyhow::{Context, Result, anyhow};
use btf::btf::{Array, Btf, Struct, Type};
use linnix_ai_ebpf_common::{TelemetryConfig, rss_source};
use std::convert::TryFrom;
use std::env;
use sysinfo::System;

const KERNEL_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const ENV_KERNEL_BTF_PATH: &str = "LINNIX_KERNEL_BTF";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreRssMode {
    SignalStruct,
    MmStruct,
}

pub struct TelemetryConfigResult {
    pub config: TelemetryConfig,
    pub mode: CoreRssMode,
    pub signal_supported: bool,
    pub mm_supported: bool,
}

pub fn derive_telemetry_config() -> Result<TelemetryConfigResult> {
    let btf_path = env::var(ENV_KERNEL_BTF_PATH).unwrap_or_else(|_| KERNEL_BTF_PATH.to_string());
    let btf = Btf::from_file(btf_path).context("failed to load kernel BTF metadata")?;

    let task_struct = expect_named_struct(&btf, "task_struct")?;

    let (real_parent_bits, _) = member_offset(task_struct, "real_parent")?;
    let (tgid_bits, _) = member_offset(task_struct, "tgid")?;
    let (pid_bits, _) = member_offset(task_struct, "pid")?;
    let (comm_bits, _) = member_offset(task_struct, "comm")?;
    let (se_bits, se_type) = member_offset(task_struct, "se")?;

    let signal_candidate = rss_layout_for_field(&btf, task_struct, "signal")?;
    let mm_candidate = rss_layout_for_field(&btf, task_struct, "mm")?;

    let signal_supported = signal_candidate.is_some();
    let mm_supported = mm_candidate.is_some();

    let chosen_mode = if mm_supported {
        CoreRssMode::MmStruct
    } else if signal_supported {
        CoreRssMode::SignalStruct
    } else {
        return Err(anyhow!(
            "rss_stat layout not found in signal_struct or mm_struct; kernel layout unsupported"
        ));
    };

    let (signal_bits, signal_layout) = match signal_candidate {
        Some((bits, layout)) => (Some(bits), Some(layout)),
        None => (None, None),
    };
    let (mm_bits, mm_layout) = match mm_candidate {
        Some((bits, layout)) => (Some(bits), Some(layout)),
        None => (None, None),
    };

    let selected_layout = match chosen_mode {
        CoreRssMode::MmStruct => mm_layout.clone().expect("mm layout missing"),
        CoreRssMode::SignalStruct => signal_layout.clone().expect("signal layout missing"),
    };

    const RSS_ENUM_CANDIDATES: [&str; 2] = ["rss_stat_item", "mm_counter_type"];
    let file_index = u32::try_from(enum_value_any(&btf, &RSS_ENUM_CANDIDATES, "MM_FILEPAGES")?)
        .context("MM_FILEPAGES index does not fit into u32")?;
    let anon_index = u32::try_from(enum_value_any(&btf, &RSS_ENUM_CANDIDATES, "MM_ANONPAGES")?)
        .context("MM_ANONPAGES index does not fit into u32")?;

    let se_struct = resolve_struct(&btf, se_type)?;
    let (sum_exec_bits, _) = member_offset(se_struct, "sum_exec_runtime")?;

    let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = if page_size_raw > 0 {
        page_size_raw as u32
    } else {
        0
    };

    let mut sys = System::new_all();
    sys.refresh_memory();
    let total_memory_bytes = sys.total_memory().saturating_mul(1024);

    let mut telemetry = TelemetryConfig::zeroed();
    telemetry.task_real_parent_offset = to_bytes(real_parent_bits)?;
    telemetry.task_tgid_offset = to_bytes(tgid_bits)?;
    telemetry.task_pid_offset = to_bytes(pid_bits)?;
    telemetry.task_comm_offset = to_bytes(comm_bits)?;
    telemetry.task_se_offset = to_bytes(se_bits)?;
    telemetry.se_sum_exec_runtime_offset = to_bytes(sum_exec_bits)?;
    telemetry.rss_count_offset = selected_layout.count_offset;
    telemetry.rss_item_size = selected_layout.item_size;
    telemetry.rss_file_index = file_index;
    telemetry.rss_anon_index = anon_index;
    telemetry.page_size = page_size;
    telemetry.total_memory_bytes = total_memory_bytes;

    if let Some(bits) = signal_bits {
        telemetry.task_signal_offset = to_bytes(bits)?;
    }
    if let Some(layout) = signal_layout {
        telemetry.signal_rss_stat_offset = layout.field_offset;
    }
    if let Some(bits) = mm_bits {
        telemetry.task_mm_offset = to_bytes(bits)?;
    }
    if let Some(layout) = mm_layout {
        telemetry.mm_rss_stat_offset = layout.field_offset;
    }

    telemetry.rss_source = match chosen_mode {
        CoreRssMode::MmStruct => rss_source::MM,
        CoreRssMode::SignalStruct => rss_source::SIGNAL,
    };

    Ok(TelemetryConfigResult {
        config: telemetry,
        mode: chosen_mode,
        signal_supported,
        mm_supported,
    })
}

#[derive(Clone)]
struct RssLayout {
    field_offset: u32,
    count_offset: u32,
    item_size: u32,
}

fn rss_layout_for_field(
    btf: &Btf,
    task_struct: &Struct,
    field: &str,
) -> Result<Option<(u32, RssLayout)>> {
    let (bits, type_id) = member_offset(task_struct, field)?;
    let container = match resolve_struct_deep(btf, type_id) {
        Ok(st) => st,
        Err(_) => return Ok(None),
    };
    let layout = match rss_layout_for_container(btf, container)? {
        Some(layout) => layout,
        None => return Ok(None),
    };
    Ok(Some((bits, layout)))
}

fn rss_layout_for_container(btf: &Btf, container: &Struct) -> Result<Option<RssLayout>> {
    let Some((rss_bits, rss_type)) = find_member_recursive(btf, container, 0, "rss_stat")? else {
        return Ok(None);
    };

    let field_offset = to_bytes(rss_bits)?;
    let layout = compute_rss_layout(btf, rss_type)?;

    Ok(Some(RssLayout {
        field_offset,
        count_offset: layout.count_offset,
        item_size: layout.item_size,
    }))
}

#[derive(Clone)]
struct PerCpuLayout {
    count_offset: u32,
    item_size: u32,
}

fn compute_rss_layout(btf: &Btf, type_id: u32) -> Result<PerCpuLayout> {
    let mut current = type_id;
    for _ in 0..32 {
        let resolved = btf
            .get_type_by_id(current)
            .with_context(|| format!("failed to resolve rss_stat type id {current}"))?;

        match &resolved.base_type {
            Type::Struct(st) => return layout_from_struct(btf, st),
            Type::Array(arr) => return layout_from_array(btf, arr),
            Type::Const(map)
            | Type::Volatile(map)
            | Type::Restrict(map)
            | Type::Typedef(map)
            | Type::TypeTag(map)
            | Type::Pointer(map) => {
                current = map.type_id;
            }
            other => {
                return Err(anyhow!("unsupported rss_stat type: {:?}", other));
            }
        }
    }

    Err(anyhow!(
        "type resolution exceeded searching for rss_stat (type id {type_id})"
    ))
}

fn layout_from_struct(btf: &Btf, rss_struct: &Struct) -> Result<PerCpuLayout> {
    let (count_bits, count_type) = member_offset(rss_struct, "count")?;
    let count_offset = to_bytes(count_bits)?;

    let array = expect_array(btf, count_type)?;
    let element_ty = btf
        .get_type_by_id(array.elem_type_id)
        .context("unable to resolve rss_stat element type")?;
    let rss_item_bits = element_ty.bits;
    if rss_item_bits == 0 || rss_item_bits % 8 != 0 {
        return Err(anyhow!(
            "unexpected rss_stat element size: {rss_item_bits} bits"
        ));
    }

    Ok(PerCpuLayout {
        count_offset,
        item_size: rss_item_bits / 8,
    })
}

fn layout_from_array(btf: &Btf, array: &Array) -> Result<PerCpuLayout> {
    let element_ty = btf
        .get_type_by_id(array.elem_type_id)
        .context("unable to resolve rss_stat element type")?;
    let element_bits = element_ty.bits;
    if element_bits == 0 || element_bits % 8 != 0 {
        return Err(anyhow!(
            "unexpected rss_stat element size: {element_bits} bits"
        ));
    }

    let element_struct = resolve_struct_deep(btf, array.elem_type_id)?;
    let (count_bits, _) = member_offset(element_struct, "count")?;

    Ok(PerCpuLayout {
        count_offset: to_bytes(count_bits)?,
        item_size: element_bits / 8,
    })
}

fn resolve_struct_deep(btf: &Btf, mut type_id: u32) -> Result<&Struct> {
    for _ in 0..32 {
        let ty = btf
            .get_type_by_id(type_id)
            .with_context(|| format!("failed to resolve type id {type_id}"))?;
        match &ty.base_type {
            Type::Struct(st) => return Ok(st),
            Type::Const(map)
            | Type::Volatile(map)
            | Type::Restrict(map)
            | Type::Typedef(map)
            | Type::TypeTag(map)
            | Type::Pointer(map) => {
                type_id = map.type_id;
            }
            other => {
                return Err(anyhow!(
                    "type id {type_id} does not resolve to a struct ({other:?})"
                ));
            }
        }
    }

    Err(anyhow!(
        "type resolution exceeded while resolving struct for type id {type_id}"
    ))
}

fn find_member_recursive(
    btf: &Btf,
    st: &Struct,
    base_bits: u32,
    target: &str,
) -> Result<Option<(u32, u32)>> {
    for member in &st.members {
        let member_bits = base_bits + member.offset;
        if member.name.as_deref() == Some(target) {
            return Ok(Some((member_bits, member.type_id)));
        }

        if is_inline_container(member.name.as_deref())
            && let Some(inner) = struct_if_inline(btf, member.type_id)?
            && let Some(result) = find_member_recursive(btf, inner, member_bits, target)?
        {
            return Ok(Some(result));
        }
    }

    Ok(None)
}

fn is_inline_container(name: Option<&str>) -> bool {
    match name {
        None => true,
        Some(n) => {
            let trimmed = n.trim();
            trimmed.is_empty() || trimmed == "(anon)"
        }
    }
}

fn struct_if_inline(btf: &Btf, mut type_id: u32) -> Result<Option<&Struct>> {
    for _ in 0..32 {
        let ty = btf
            .get_type_by_id(type_id)
            .with_context(|| format!("failed to resolve nested type id {type_id}"))?;
        match &ty.base_type {
            Type::Struct(st) => return Ok(Some(st)),
            Type::Const(map)
            | Type::Volatile(map)
            | Type::Restrict(map)
            | Type::Typedef(map)
            | Type::TypeTag(map) => {
                type_id = map.type_id;
            }
            Type::Pointer(_) | Type::Array(_) | Type::Union(_) => return Ok(None),
            _ => return Ok(None),
        }
    }

    Err(anyhow!(
        "type resolution exceeded while examining nested struct (type id {type_id})"
    ))
}

fn expect_named_struct<'a>(btf: &'a Btf, name: &str) -> Result<&'a Struct> {
    let ty = btf
        .get_type_by_name(name)
        .with_context(|| format!("type {name} not found in BTF"))?;
    match &ty.base_type {
        Type::Struct(st) => Ok(st),
        other => Err(anyhow!("type {name} is not a struct (found {:?})", other)),
    }
}

fn resolve_struct(btf: &Btf, type_id: u32) -> Result<&Struct> {
    let ty = btf
        .get_type_by_id(type_id)
        .with_context(|| format!("failed to resolve type id {type_id}"))?;
    match &ty.base_type {
        Type::Struct(st) => Ok(st),
        other => Err(anyhow!(
            "expected struct for type id {type_id}, found {:?}",
            other
        )),
    }
}

fn expect_array(btf: &Btf, type_id: u32) -> Result<Array> {
    let ty = btf
        .get_type_by_id(type_id)
        .with_context(|| format!("failed to resolve array type id {type_id}"))?;
    match &ty.base_type {
        Type::Array(arr) => Ok(*arr),
        other => Err(anyhow!("expected array, found {:?}", other)),
    }
}

fn member_offset(st: &Struct, name: &str) -> Result<(u32, u32)> {
    st.members
        .iter()
        .find(|member| member.name.as_deref() == Some(name))
        .map(|member| (member.offset, member.type_id))
        .ok_or_else(|| anyhow!("member {name} not found"))
}

fn enum_value_any(btf: &Btf, enum_names: &[&str], variant: &str) -> Result<u64> {
    for name in enum_names {
        if let Ok(value) = enum_value(btf, name, variant) {
            return Ok(value);
        }
    }

    for ty in btf.get_types() {
        match &ty.base_type {
            Type::Enum32(en) | Type::Enum64(en) => {
                if let Some(entry) = en
                    .entries
                    .iter()
                    .find(|entry| entry.name.as_deref() == Some(variant))
                {
                    return u64::try_from(entry.value).map_err(|_| {
                        anyhow!("enum variant {variant} has negative value {}", entry.value)
                    });
                }
            }
            _ => {}
        }
    }

    Err(anyhow!(
        "enum variant {variant} not found in {:?} or anonymous enums",
        enum_names
    ))
}

fn enum_value(btf: &Btf, enum_name: &str, variant: &str) -> Result<u64> {
    let ty = btf
        .get_type_by_name(enum_name)
        .with_context(|| format!("enum {enum_name} not found"))?;
    match &ty.base_type {
        Type::Enum32(en) => en
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some(variant))
            .map(|entry| entry.value as u64)
            .ok_or_else(|| anyhow!("enum variant {variant} not found")),
        Type::Enum64(en) => en
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some(variant))
            .map(|entry| entry.value as u64)
            .ok_or_else(|| anyhow!("enum variant {variant} not found")),
        other => Err(anyhow!(
            "type {enum_name} is not an enum (found {:?})",
            other
        )),
    }
}

#[allow(clippy::manual_is_multiple_of)] // is_multiple_of not stable in nightly-2024-12-10
fn to_bytes(bits: u32) -> Result<u32> {
    if bits % 8 == 0 {
        Ok(bits / 8)
    } else {
        Err(anyhow!("member offset {bits} is not byte aligned"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_bytes_roundtrip() {
        assert_eq!(to_bytes(0).unwrap(), 0);
        assert_eq!(to_bytes(8).unwrap(), 1);
        assert!(to_bytes(3).is_err());
    }
}
