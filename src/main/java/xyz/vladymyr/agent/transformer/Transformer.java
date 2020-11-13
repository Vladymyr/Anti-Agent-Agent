package xyz.vladymyr.agent.transformer;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.function.BiPredicate;
import java.util.function.Predicate;

import static org.objectweb.asm.Opcodes.*;

/**
 * The user provides an implementation of this interface in order
 * to transform class files. The transformation will occur before the class is defined by the JVM
 * or after by redefining it.
 *
 * @author Vladymyr
 * @version 04/10/2019
 * @since 1.2
 */
public interface Transformer {

	/**
	 * A default implementation of Transformer which only consists in
	 * emptying the given method.
	 */
	Transformer CLEANER = new Transformer() {
		@Override
		public boolean transform(MethodNode methodNode, InsnList insnList, AbstractInsnNode insn) {
			emptyMethod(methodNode);

			return true;
		}
	};

	static Builder builder() {
		return new Builder();
	}

	/**
	 * @param methodNode method to be transformed
	 * @param insnList   list of instructions of the method node
	 * @param insn       current instruction to be processed
	 * @return
	 */
	boolean transform(MethodNode methodNode, InsnList insnList, AbstractInsnNode insn);

	/**
	 * Default method in charge of iterating through given method's instructions
	 * applying the transformer to each of them. The loop will break once the transformers
	 * requests it to.
	 *
	 * @param methodNode method node to transform
	 */
	default void process(MethodNode methodNode) {
		InsnList methodInstructions = methodNode.instructions;
		AbstractInsnNode[] array = methodInstructions.toArray();
		boolean breakLoop = false;
		for (AbstractInsnNode insn : array) {
			if (breakLoop) {
				break;
			}

			breakLoop = this.transform(methodNode, methodInstructions, insn);
		}
	}

	/**
	 * Cleans method's instructions and replaces them with a
	 * generated return.
	 *
	 * @param methodNode method to empty
	 */
	default void emptyMethod(MethodNode methodNode) {
		methodNode.instructions.clear();
		generateReturn(methodNode.instructions, methodNode.desc);

		methodNode.tryCatchBlocks.clear();
		methodNode.localVariables.clear();
		methodNode.exceptions.clear();
	}

	/**
	 * Generates a return based on the given method description
	 *
	 * @param instructions list of instuction to add the generated return
	 * @param desc         description of the method in order to generate a proper set of return instructions
	 */
	default void generateReturn(InsnList instructions, String desc) {
		final InsnNode returnNode;
		switch (Type.getReturnType(desc).getSort()) {
			case Type.VOID:
				returnNode = new InsnNode(RETURN);
				break;
			case Type.BOOLEAN:
			case Type.CHAR:
			case Type.BYTE:
			case Type.SHORT:
			case Type.INT:
				instructions.add(new InsnNode(ICONST_0));
				returnNode = new InsnNode(IRETURN);
				break;
			case Type.FLOAT:
				instructions.add(new InsnNode(FCONST_0));
				returnNode = new InsnNode(FRETURN);
				break;
			case Type.LONG:
				instructions.add(new InsnNode(LCONST_0));
				returnNode = new InsnNode(LRETURN);
				break;
			case Type.DOUBLE:
				instructions.add(new InsnNode(DCONST_0));
				returnNode = new InsnNode(DRETURN);
				break;
			case Type.ARRAY:
			case Type.OBJECT:
				instructions.add(new InsnNode(ACONST_NULL));
				returnNode = new InsnNode(ARETURN);
				break;
			case Type.METHOD:
			default:
				throw new IllegalStateException("Unexpected value: " + Type.getReturnType(desc).getSort());
		}

		instructions.add(returnNode);
	}

	class Builder {
		boolean filtered;
		private BiPredicate<Class<?>, ClassNode> clsFilter;
		private Predicate<MethodNode> methodFilter;
		private Transformer transformer;

		private Builder() {
			super();
		}

		public Builder withClassFilter(BiPredicate<Class<?>, ClassNode> clsFilter) {
			this.clsFilter = clsFilter;
			this.filtered = true;

			return this;
		}

		public Builder withMethodFilter(Predicate<MethodNode> methodFilter) {
			this.methodFilter = methodFilter;
			this.filtered = true;

			return this;
		}

		public Builder transformer(Transformer transformer) {
			this.transformer = transformer;
			return this;
		}

		public Transformer build() {
			if (filtered) {
				return new FilteredTransformer() {
					@Override
					public boolean validateClass(Class<?> cls, ClassNode classNode) {
						if (clsFilter == null) {
							return true;
						}

						return clsFilter.test(cls, classNode);
					}

					@Override
					public boolean validateMethod(MethodNode methodNode) {
						if (methodFilter == null) {
							return true;
						}

						return methodFilter.test(methodNode);
					}

					@Override
					public boolean transform(MethodNode methodNode, InsnList insnList, AbstractInsnNode insn) {
						return transformer.transform(methodNode, insnList, insn);
					}
				};
			} else {
				return (methodNode, insnList, insn) -> transformer.transform(methodNode, insnList, insn);
			}
		}
	}

}
