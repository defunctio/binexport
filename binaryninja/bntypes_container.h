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


#ifndef BINJADIFF_BNTYPESCONTAINER_H
#define BINJADIFF_BNTYPESCONTAINER_H

#include <types_container.h>
#include <virtual_memory.h>

class Function;

class BNTypesContainer : public TypesContainer {
 public:
  explicit BNTypesContainer(AddressSpace addressSpace);

  ~BNTypesContainer() override = default;

  void GatherTypes() override;

  TypeReference ResolveTypeReference(Address address, size_t operand_num) const override;

  TypeReference
  ResolveDisplacedTypeReference(Address address, Address displacement, size_t operand_num) const override;

  TypeReference ResolveMemoryTypeReference(Address immediate) const override;

  virtual const BaseType::BaseTypes &GetBaseTypes() const { return _base_types; };

  virtual const BaseType::MemberTypes &GetMemberTypes() const { return _member_types; };

  const BaseType *GetStackFrame(const Function &function) const override;

  void CreateFunctionPrototype(const Function &function) override;

  const BaseType *GetFunctionPrototype(const Function &function) const override;

  BaseType::BaseTypes _base_types;
  BaseType::MemberTypes _member_types;
};

#endif //BINJADIFF_BNTYPESCONTAINER_H
