//  MIT License
//
//  Copyright (c) <2017> <NOP Developments LLC> (https://keybase.io/defunct)
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//          of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//          to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//          copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//          The above copyright notice and this permission notice shall be included in all
//          copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//          AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

#include "bntypes_container.h"

BNTypesContainer::BNTypesContainer(AddressSpace addressSpace) : TypesContainer() {

}

void BNTypesContainer::GatherTypes() {

}

TypesContainer::TypeReference BNTypesContainer::ResolveTypeReference(Address address, size_t operand_num) const {
  return TypeReference::CreateEmptyReference();
}

TypesContainer::TypeReference
BNTypesContainer::ResolveDisplacedTypeReference(Address address, Address displacement, size_t operand_num) const {
  return TypeReference::CreateEmptyReference();
}

TypesContainer::TypeReference BNTypesContainer::ResolveMemoryTypeReference(Address immediate) const {
  return TypeReference::CreateEmptyReference();
}

const BaseType *BNTypesContainer::GetStackFrame(const Function &function) const {
  return nullptr;
}

void BNTypesContainer::CreateFunctionPrototype(const Function &function) {

}

const BaseType *BNTypesContainer::GetFunctionPrototype(const Function &function) const {
  return nullptr;
}
