//! Bounded WASM module parser producing the normalized module model (#71 搂2).
//!
//! Uses `wasmparser` (Bytecode Alliance) as the embedded parser. Decoding is
//! budgeted: a hostile/deeply-nested module fails locally with a diagnostic
//! instead of exhausting memory or hanging the worker.

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// One section with its byte range (exact offsets, provenance for every
/// downstream query).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub id: u8,
    pub name: String,
    /// Offset of the section payload in the file.
    pub offset: u64,
    pub size: u64,
}

/// A function type (signature).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuncType {
    pub params: Vec<String>,
    pub results: Vec<String>,
}

/// An import entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub module: String,
    pub name: String,
    pub kind: String,
    /// For func imports: type index. Others: None.
    pub type_index: Option<u32>,
    /// WASI grouping: true when the import module is a WASI namespace.
    pub wasi: bool,
}

/// An export entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: String,
    pub kind: String,
    /// Function index / table index / memory index / global index by kind.
    pub index: u32,
}

/// A defined function: index-space entry plus code-body range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    /// Function index space (imports occupy the low indices).
    pub index: u32,
    pub type_index: u32,
    /// Offset of the locals+body payload start.
    pub code_offset: u64,
    pub code_size: u64,
    /// Declared local types (params live in the type).
    pub local_types: Vec<String>,
    /// Name from the name custom section, when present.
    pub name: Option<String>,
}

/// A global.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalEntry {
    pub index: u32,
    pub ty: String,
    pub mutable: bool,
    /// Init expression rendering (const), when a plain constant.
    pub init: Option<String>,
}

/// A table definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableEntry {
    pub index: u32,
    pub elem_ty: String,
    pub initial: u64,
    pub maximum: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElementSegment {
    pub index: u32,
    pub table_index: u32,
    /// Constant offset for active segments with a const init expr.
    pub offset: Option<u64>,
    /// Function indices referenced (funcref payload).
    pub func_indices: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub index: u32,
    pub initial_pages: u64,
    pub maximum_pages: Option<u64>,
    pub shared: bool,
    pub memory64: bool,
    pub page_size_log2: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSegment {
    pub index: u32,
    pub memory_index: u32,
    /// Constant offset when the init expr is a plain constant.
    pub offset: Option<u64>,
    /// Length of payload; bytes are re-read from the file on demand
    /// (never duplicated into the model - bounded memory).
    pub len: u32,
    pub file_offset: u64,
}

/// Which modern proposals the module actually uses (issue 搂8: never
/// MVP-only; unsupported features fail explicitly, not silently).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureMap {
    pub multi_value: bool,
    pub bulk_memory: bool,
    pub reference_types: bool,
    pub simd: bool,
    pub relaxed_simd: bool,
    pub tail_call: bool,
    pub exception_handling: bool,
    pub threads: bool,
    pub memory64: bool,
    pub multi_memory: bool,
    pub function_references: bool,
    pub gc: bool,
}

/// Custom sections of interest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustomInfo {
    pub name_section: bool,
    pub producers: Option<Vec<(String, String)>>,
    pub other_names: Vec<String>,
}

/// The normalized module model: everything the query actions expose.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleModel {
    pub version: u16,
    pub sections: Vec<SectionInfo>,
    pub types: Vec<FuncType>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub functions: Vec<FunctionEntry>,
    pub globals: Vec<GlobalEntry>,
    pub tables: Vec<TableEntry>,
    pub elements: Vec<ElementSegment>,
    pub memories: Vec<MemoryEntry>,
    pub datas: Vec<DataSegment>,
    pub features: FeatureMap,
    pub custom: CustomInfo,
    /// Start function index, when present.
    pub start: Option<u32>,
    /// Count of imported functions (the defined-function index space starts
    /// here; every mapping depends on it).
    pub imported_functions: u32,
    /// sha256 of the binary, set by the caller (cache key component).
    pub binary_sha256: String,
}

/// Parse budget: caps so adversarial modules fail locally (issue 搂9).
#[derive(Debug, Clone, Copy)]
pub struct ParseBudget {
    pub max_sections: usize,
    pub max_types: usize,
    pub max_functions: usize,
    pub max_elements: usize,
    pub max_datas: usize,
}

impl Default for ParseBudget {
    fn default() -> Self {
        Self {
            max_sections: 4096,
            max_types: 100_000,
            max_functions: 500_000,
            max_elements: 100_000,
            max_datas: 100_000,
        }
    }
}

fn perr(e: wasmparser::BinaryReaderError) -> Error {
    Error::Parse {
        offset: e.offset() as u64,
        message: e.message().to_string(),
    }
}

/// Record one section's byte range in the model (bounded by max_sections).
fn record_section(model: &mut ModuleModel, id: u8, name: &str, range: std::ops::Range<usize>) {
    if model.sections.len() < model_max_sections() {
        model.sections.push(SectionInfo {
            id,
            name: name.to_string(),
            offset: range.start as u64,
            size: (range.end - range.start) as u64,
        });
    }
}

fn model_max_sections() -> usize {
    4096 // mirrors ParseBudget::default().max_sections
}

/// Parse a full WASM binary into the model. `bytes` is the whole file.
pub fn parse(bytes: &[u8]) -> Result<ModuleModel> {
    parse_with_budget(bytes, &ParseBudget::default())
}

pub fn parse_with_budget(bytes: &[u8], budget: &ParseBudget) -> Result<ModuleModel> {
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        return Err(Error::Parse {
            offset: 0,
            message: "not a WASM module (bad magic)".into(),
        });
    }
    let version = u16::from_le_bytes([bytes[6], bytes[7]]);

    let mut model = ModuleModel {
        version,
        ..Default::default()
    };
    let mut feature = FeatureMap::default();
    let mut imported_functions = 0u32;
    let mut defined_fn_cursor = 0usize;

    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| Error::Parse {
            offset: e.offset() as u64,
            message: e.message().to_string(),
        })?;
        use wasmparser::Payload::*;
        match payload {
            Version { .. } => {}
            TypeSection(r) => {
                record_section(&mut model, 1, "type", r.range());
                for group in r {
                    let group = group.map_err(perr)?;
                    for sub in group.types() {
                        if model.types.len() >= budget.max_types {
                            return Err(Error::Budget("types"));
                        }
                        let ft = match &sub.composite_type.inner {
                            wasmparser::CompositeInnerType::Func(f) => FuncType {
                                params: f.params().iter().map(|p| p.to_string()).collect(),
                                results: f.results().iter().map(|p| p.to_string()).collect(),
                            },
                            wasmparser::CompositeInnerType::Struct(_) => {
                                feature.gc = true;
                                FuncType {
                                    params: vec!["struct".into()],
                                    results: vec![],
                                }
                            }
                            wasmparser::CompositeInnerType::Array(_) => {
                                feature.gc = true;
                                FuncType {
                                    params: vec!["array".into()],
                                    results: vec![],
                                }
                            }
                            wasmparser::CompositeInnerType::Cont(_) => {
                                return Err(Error::Parse {
                                    offset: 0,
                                    message: "stack switching (cont) types unsupported".into(),
                                });
                            }
                        };
                        model.types.push(ft);
                    }
                }
            }
            ImportSection(r) => {
                record_section(&mut model, 2, "import", r.range());
                for imp in r {
                    let imp = imp.map_err(perr)?;
                    let (kind, tidx) = match imp.ty {
                        wasmparser::TypeRef::Func(t) => {
                            imported_functions += 1;
                            ("func", Some(t))
                        }
                        wasmparser::TypeRef::Table(_) => ("table", None),
                        wasmparser::TypeRef::Memory(_) => ("memory", None),
                        wasmparser::TypeRef::Global(_) => ("global", None),
                        wasmparser::TypeRef::Tag(_) => ("tag", None),
                    };
                    let wasi = imp.module.starts_with("wasi_")
                        || imp.module == "wasi_unstable"
                        || imp.module == "wasi_snapshot_preview1";
                    model.imports.push(ImportEntry {
                        module: imp.module.to_string(),
                        name: imp.name.to_string(),
                        kind: kind.into(),
                        type_index: tidx,
                        wasi,
                    });
                }
            }
            FunctionSection(r) => {
                record_section(&mut model, 3, "function", r.range());
                for (i, t) in r.into_iter().enumerate() {
                    let t = t.map_err(perr)?;
                    if model.functions.len() >= budget.max_functions {
                        return Err(Error::Budget("functions"));
                    }
                    model.functions.push(FunctionEntry {
                        index: imported_functions + i as u32,
                        type_index: t,
                        code_offset: 0,
                        code_size: 0,
                        local_types: vec![],
                        name: None,
                    });
                }
            }
            TableSection(r) => {
                record_section(&mut model, 4, "table", r.range());
                for (index, t) in r.into_iter().enumerate() {
                    let t = t.map_err(perr)?;
                    if wasmparser::ValType::Ref(t.ty.element_type).is_reference_type() {
                        feature.reference_types = true;
                    }
                    model.tables.push(TableEntry {
                        index: index as u32,
                        elem_ty: wasmparser::ValType::Ref(t.ty.element_type).to_string(),
                        initial: t.ty.initial,
                        maximum: t.ty.maximum,
                    });
                }
            }
            MemorySection(r) => {
                record_section(&mut model, 5, "memory", r.range());
                for (index, m) in r.into_iter().enumerate() {
                    let m = m.map_err(perr)?;
                    if index >= 1 {
                        feature.multi_memory = true;
                    }
                    if m.memory64 {
                        feature.memory64 = true;
                    }
                    if m.shared {
                        feature.threads = true;
                    }
                    model.memories.push(MemoryEntry {
                        index: index as u32,
                        initial_pages: m.initial,
                        maximum_pages: m.maximum,
                        shared: m.shared,
                        memory64: m.memory64,
                        page_size_log2: m.page_size_log2,
                    });
                }
            }
            GlobalSection(r) => {
                record_section(&mut model, 6, "global", r.range());
                for (index, g) in r.into_iter().enumerate() {
                    let g = g.map_err(perr)?;
                    let init =
                        g.init_expr
                            .get_operators_reader()
                            .read()
                            .ok()
                            .and_then(|op| match op {
                                wasmparser::Operator::I32Const { value } => Some(value.to_string()),
                                wasmparser::Operator::I64Const { value } => Some(value.to_string()),
                                wasmparser::Operator::F32Const { value } => {
                                    Some(f32::from_bits(value.bits()).to_string())
                                }
                                wasmparser::Operator::F64Const { value } => {
                                    Some(f64::from_bits(value.bits()).to_string())
                                }
                                _ => None,
                            });
                    model.globals.push(GlobalEntry {
                        index: index as u32,
                        ty: g.ty.content_type.to_string(),
                        mutable: g.ty.mutable,
                        init,
                    });
                }
            }
            ExportSection(r) => {
                record_section(&mut model, 7, "export", r.range());
                for e in r {
                    let e = e.map_err(perr)?;
                    let kind = match e.kind {
                        wasmparser::ExternalKind::Func => "func",
                        wasmparser::ExternalKind::Table => "table",
                        wasmparser::ExternalKind::Memory => "memory",
                        wasmparser::ExternalKind::Global => "global",
                        wasmparser::ExternalKind::Tag => "tag",
                    };
                    model.exports.push(ExportEntry {
                        name: e.name.to_string(),
                        kind: kind.into(),
                        index: e.index,
                    });
                }
            }
            StartSection { func, .. } => {
                model.start = Some(func);
            }
            ElementSection(r) => {
                record_section(&mut model, 9, "elem", r.range());
                for (index, e) in r.into_iter().enumerate() {
                    let e = e.map_err(perr)?;
                    if model.elements.len() >= budget.max_elements {
                        return Err(Error::Budget("elements"));
                    }
                    let mut seg = ElementSegment {
                        index: index as u32,
                        table_index: 0,
                        offset: None,
                        func_indices: vec![],
                    };
                    match e.kind {
                        wasmparser::ElementKind::Active {
                            table_index,
                            offset_expr,
                        } => {
                            seg.table_index = table_index.unwrap_or(0);
                            seg.offset = const_expr_u64(&offset_expr);
                        }
                        wasmparser::ElementKind::Passive | wasmparser::ElementKind::Declared => {}
                    }
                    if let wasmparser::ElementItems::Functions(f) = e.items {
                        seg.func_indices = f.into_iter().filter_map(|x| x.ok()).collect();
                    }
                    model.elements.push(seg);
                }
            }
            CodeSectionStart { range, .. } => {
                record_section(&mut model, 10, "code", range);
            }
            CodeSectionEntry(f) => {
                let entry = model
                    .functions
                    .get_mut(defined_fn_cursor)
                    .ok_or(Error::Budget("code entries exceed declared functions"))?;
                let mut locals = f.get_locals_reader().map_err(perr)?;
                let count = locals.get_count();
                let mut local_types = Vec::new();
                for _ in 0..count {
                    let (n, ty) = locals.read().map_err(perr)?;
                    for _ in 0..n {
                        local_types.push(ty.to_string());
                    }
                }
                entry.local_types = local_types;
                let range = f.range();
                entry.code_offset = range.start as u64;
                entry.code_size = range.end as u64 - range.start as u64;
                defined_fn_cursor += 1;
            }
            DataSection(r) => {
                record_section(&mut model, 11, "data", r.range());
                for (index, d) in r.into_iter().enumerate() {
                    let d = d.map_err(perr)?;
                    if model.datas.len() >= budget.max_datas {
                        return Err(Error::Budget("datas"));
                    }
                    feature.bulk_memory = true;
                    let mut seg = DataSegment {
                        index: index as u32,
                        memory_index: 0,
                        offset: None,
                        len: d.data.len() as u32,
                        file_offset: d.range.start as u64,
                    };
                    if let wasmparser::DataKind::Active {
                        memory_index,
                        offset_expr,
                    } = d.kind
                    {
                        seg.memory_index = memory_index;
                        seg.offset = const_expr_u64(&offset_expr);
                    }
                    model.datas.push(seg);
                }
            }
            TagSection(r) => {
                record_section(&mut model, 13, "tag", r.range());
                for _ in r {}
                feature.exception_handling = true;
            }
            CustomSection(c) => match c.name() {
                "name" => {
                    model.custom.name_section = true;
                    // Bounded name-section walk: the function-name subsection
                    // maps function indices to names.
                    let reader = wasmparser::NameSectionReader::new(wasmparser::BinaryReader::new(
                        c.data(),
                        c.data_offset(),
                    ));
                    for sub in reader {
                        let sub = match sub {
                            Ok(s) => s,
                            Err(_) => break,
                        };
                        if let wasmparser::Name::Function(names) = sub {
                            for item in names {
                                let item = match item {
                                    Ok(x) => x,
                                    Err(_) => continue,
                                };
                                if let Some(f) =
                                    model.functions.iter_mut().find(|f| f.index == item.index)
                                {
                                    f.name = Some(item.name.to_string());
                                }
                            }
                        }
                    }
                }
                "producers" => {
                    let mut out = vec![];
                    let prod = match wasmparser::ProducersSectionReader::new(
                        wasmparser::BinaryReader::new(c.data(), c.data_offset()),
                    ) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    for field in prod {
                        let field = match field {
                            Ok(f) => f,
                            Err(_) => continue,
                        };
                        for value in field.values {
                            let value = match value {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            out.push((field.name.to_string(), value.name.to_string()));
                        }
                    }
                    model.custom.producers = Some(out);
                }
                other => model.custom.other_names.push(other.to_string()),
            },
            _ => {}
        }
    }

    if model
        .functions
        .iter()
        .any(|f| f.local_types.iter().any(|t| t.contains("v128")))
    {
        feature.simd = true;
    }
    model.features = feature;
    model.imported_functions = imported_functions;
    Ok(model)
}

fn const_expr_u64(expr: &wasmparser::ConstExpr) -> Option<u64> {
    let mut ops = expr.get_operators_reader();
    match ops.read().ok()? {
        wasmparser::Operator::I32Const { value } => Some(value as u32 as u64),
        wasmparser::Operator::I64Const { value } => Some(value as u64),
        _ => None,
    }
}
