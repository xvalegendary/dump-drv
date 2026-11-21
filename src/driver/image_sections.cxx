#include "image_sections.hxx"

#include "shared/pe.hxx"

namespace {

constexpr ULONG header_read_size = 0x1000;

alignas(16) unsigned char header_buffer[header_read_size];

}

namespace dump::driver {

NTSTATUS ImageSections::query(ProcessSnapshot& snapshot, protocol::SectionsResponse& response) noexcept {
    response = protocol::SectionsResponse{};
    const auto base = snapshot.image_base();
    if (base == 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    SIZE_T transferred{};
    auto status = snapshot.read(base, header_buffer, header_read_size, transferred);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (transferred < pe::minimum_headers) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    pe::Image image{};
    if (pe::parse(header_buffer, static_cast<protocol::usize>(transferred), image) != Status::success) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    response.image_base = base;
    response.image_size = image.image_size;
    response.headers_size = pe::header_extent(image);
    response.section_count = image.section_count;
    for (protocol::u32 index = 0; index < image.section_count; ++index) {
        const auto& source = image.sections[index];
        auto& destination = response.sections[index];
        for (protocol::u32 position = 0; position < protocol::section_name_size; ++position) {
            destination.name[position] = source.name[position];
        }
        destination.virtual_address = source.virtual_address;
        destination.virtual_size = source.virtual_size;
        destination.raw_offset = source.raw_offset;
        destination.raw_size = source.raw_size;
        destination.characteristics = source.characteristics;
    }
    response.native_status = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

}